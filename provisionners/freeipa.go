package provisioners

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	api "github.com/guilhem/freeipa-issuer/api/v1beta1"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/xu001186/go-freeipa/freeipa"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var collection = new(sync.Map)

// FreeIPAPKI
type FreeIPAPKI struct {
	client *freeipa.Client
	spec   *api.IssuerSpec

	name string
}

// New returns a new provisioner, configured with the information in the
// given issuer.
func New(namespacedName types.NamespacedName, spec *api.IssuerSpec, user, password string, insecure bool) (*FreeIPAPKI, error) {

	tspt := http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	client, err := freeipa.Connect(time.Second*30, spec.Host, &tspt, user, password)
	if err != nil {
		return nil, err
	}

	p := &FreeIPAPKI{
		name:   fmt.Sprintf("%s.%s", namespacedName.Name, namespacedName.Namespace),
		client: client,
		spec:   spec,
	}

	return p, nil
}

// Load returns a provisioner by NamespacedName.
func Load(namespacedName types.NamespacedName) (*FreeIPAPKI, bool) {
	v, ok := collection.Load(namespacedName)
	if !ok {
		return nil, ok
	}
	p, ok := v.(*FreeIPAPKI)
	return p, ok
}

// Store adds a new provisioner to the collection by NamespacedName.
func Store(namespacedName types.NamespacedName, provisioner *FreeIPAPKI) {
	collection.Store(namespacedName, provisioner)
}

type CertPem []byte
type CaPem []byte

const certKey = "certificate"

// Sign sends the certificate requests to the CA and returns the signed
// certificate.
func (s *FreeIPAPKI) Sign(ctx context.Context, cr *certmanager.CertificateRequest) (CertPem, CaPem, error) {
	log := log.FromContext(ctx).WithName("sign").WithValues("request", cr)

	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CSR for signing: %s", err)
	}

	if csr.Subject.CommonName == "" {
		return nil, nil, fmt.Errorf("request has no common name")
	}

	dnsNames := csr.DNSNames
	commonServiceName := fmt.Sprintf("%s/%s", s.spec.ServiceName, csr.Subject.CommonName)
	servicenames := []string{}
	servicenames = append(servicenames, commonServiceName)
	for _, dnsname := range dnsNames {
		san := fmt.Sprintf("%s/%s@%s", s.spec.ServiceName, dnsname, s.spec.RealmDomain)
		if !slices.Contains(servicenames, san) {
			servicenames = append(servicenames, san)
		}
	}

	// Adding Host
	if s.spec.AddHost {
		if _, err := s.client.HostShow(&freeipa.HostShowArgs{Fqdn: csr.Subject.CommonName}, &freeipa.HostShowOptionalArgs{}); err != nil {
			if ipaE, ok := err.(*freeipa.Error); ok && ipaE.Code == freeipa.NotFoundCode {
				if _, err := s.client.HostAdd(&freeipa.HostAddArgs{
					Fqdn: csr.Subject.CommonName,
				}, &freeipa.HostAddOptionalArgs{
					Force: freeipa.Bool(true),
				}); err != nil {
					return nil, nil, fmt.Errorf("fail adding host: %v", err)
				}
			} else {
				return nil, nil, fmt.Errorf("fail getting Host wi: %v", err)
			}
		}
	}

	// Adding service
	if s.spec.AddService {
		svcList, err := s.client.ServiceFind(
			commonServiceName,
			&freeipa.ServiceFindArgs{},
			&freeipa.ServiceFindOptionalArgs{
				PkeyOnly:  freeipa.Bool(true),
				Sizelimit: freeipa.Int(1),
			})

		if err != nil {
			if !s.spec.IgnoreError {
				return nil, nil, fmt.Errorf("fail listing services: %v", err)
			}
		} else if svcList.Count == 0 {
			if _, err := s.client.ServiceAdd(&freeipa.ServiceAddArgs{Krbcanonicalname: commonServiceName}, &freeipa.ServiceAddOptionalArgs{
				Force: freeipa.Bool(true),
			}); err != nil && !s.spec.IgnoreError {
				return nil, nil, fmt.Errorf("fail adding service: %v", err)
			}
		}
	}
	for _, servicename := range servicenames {
		_, err := s.client.ServiceAddPrincipal(&freeipa.ServiceAddPrincipalArgs{
			Krbcanonicalname: commonServiceName,
			Krbprincipalname: []string{servicename},
		}, &freeipa.ServiceAddPrincipalOptionalArgs{})
		if err != nil {
			if freeipaErr, ok := err.(*freeipa.Error); ok {
				if freeipaErr.Name == "AlreadyContainsValueError" {
					continue
				}

			}
			return nil, nil, fmt.Errorf("fail to add service principle %s to service %s : %v", commonServiceName, servicename, err)
		}
	}

	certRequestResult, err := s.client.CertRequest(&freeipa.CertRequestArgs{
		Csr:       string(cr.Spec.Request),
		Principal: commonServiceName,
	}, &freeipa.CertRequestOptionalArgs{
		Cacn: &s.spec.Ca,
		Add:  &s.spec.AddPrincipal,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("fail to request certificate: %v", err)
	}

	reqCertShow := &freeipa.CertShowArgs{
		SerialNumber: (certRequestResult.Result.(map[string]interface{})["serial_number"].(string)),
	}

	var certPem string
	var caPem string

	cert, err := s.client.CertShow(reqCertShow, &freeipa.CertShowOptionalArgs{Chain: freeipa.Bool(true)})

	if err != nil {
		log.Error(err, "fail to get certificate FALLBACK", "requestResult", certRequestResult)

		c, ok := certRequestResult.Result.(map[string]interface{})[certKey].(string)
		if !ok || c == "" {
			return nil, nil, fmt.Errorf("can't find certificate for: %s", certRequestResult.String())
		}
		certPem = formatCertificate(c)
	}

	if cert.Result.CertificateChain != nil {
		certificateChains, _ := (*(cert.Result.CertificateChain)).([]interface{})
		if len(certificateChains) > 0 {
			for i, raw_chain := range certificateChains {
				chain, _ := raw_chain.(map[string]interface{})
				cert, _ := chain["__base64__"].(string)

				c := formatCertificate(cert)
				if i == 0 {
					certPem = c
				} else {
					caPem = strings.Join([]string{caPem, c}, "\n\n")
				}
			}
		} else {
			log.Info("can't find the certificate chain for certificate %s", reqCertShow.SerialNumber)
			c, ok := certRequestResult.Result.(map[string]interface{})[certKey].(string)
			if !ok || c == "" {
				return nil, nil, fmt.Errorf("can't find certificate for: %s", certRequestResult.String())
			}
			certPem = formatCertificate(c)
		}

	}

	return []byte(strings.TrimSpace(certPem)), []byte(strings.TrimSpace(caPem)), nil
}

func formatCertificate(cert string) string {
	header := "-----BEGIN CERTIFICATE-----"
	footer := "-----END CERTIFICATE-----"
	if !strings.HasPrefix(cert, header) {
		cert = strings.Join([]string{header, cert}, "\n")
	}
	if !strings.HasSuffix(cert, footer) {
		cert = strings.Join([]string{cert, footer}, "\n")
	}
	return cert
}
