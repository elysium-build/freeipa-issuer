package controller

import (
	"context"
	"fmt"
	"time"

	api "github.com/guilhem/freeipa-issuer/api/v1beta1"
	provisioners "github.com/guilhem/freeipa-issuer/provisionners"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CertificateRequestReconciler implements a controller that reconciles CertificateRequests
// that references this controller.
type CertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Clock                  clock.Clock
	CheckApprovedCondition bool
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch

// Reconcile reconciles CertificateRequest by fetching a Cloudflare API provisioner from
// the referenced Issuer, and providing the request's CSR.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx).WithValues("certificaterequest", req.NamespacedName)

	log.Info("begin")

	cr := &certmanager.CertificateRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, client.IgnoreNotFound(err)
		}

		log.Error(err, "failed to retrieve certificate request")

		return reconcile.Result{}, err
	}

	if cr.Spec.IssuerRef.Group != "" && cr.Spec.IssuerRef.Group != api.GroupVersion.Group {
		log.Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)

		return reconcile.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(cr, certmanager.CertificateRequestCondition{
		Type:   certmanager.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return reconcile.Result{}, nil
	}
	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(cr, certmanager.CertificateRequestCondition{
		Type:   certmanager.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: certmanager.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return reconcile.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(cr, certmanager.CertificateRequestCondition{
		Type:   certmanager.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: certmanager.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return reconcile.Result{}, nil
	}

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(cr) {
		log.Info("CertificateRequest has been denied. Marking as failed.")

		if cr.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			cr.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		return reconcile.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionFalse, certmanager.CertificateRequestReasonDenied, message)
	}

	if r.CheckApprovedCondition {
		// If CertificateRequest has not been approved, exit early.
		if !cmutil.CertificateRequestIsApproved(cr) {
			log.Info("certificate request has not been approved")
			return reconcile.Result{}, nil
		}
	}

	if len(cr.Status.Certificate) > 0 {
		log.Info("existing certificate data found in status, skipping already completed certificate request")

		return reconcile.Result{}, nil
	}

	if cr.Spec.IsCA {
		log.Info("FreeIPA Issuer does not support signing of CA certificates")

		return reconcile.Result{}, nil
	}

	log.Info("validation ok")

	var issNamespaceName types.NamespacedName

	if cr.Spec.IssuerRef.Kind == "Issuer" {
		iss := api.Issuer{}
		issNamespaceName = types.NamespacedName{
			Namespace: req.Namespace,
			Name:      cr.Spec.IssuerRef.Name,
		}

		if err := r.Client.Get(ctx, issNamespaceName, &iss); err != nil {
			log.Error(err, "failed to retrieve Issuer resource", "namespace", issNamespaceName.Namespace, "name", issNamespaceName.Name)
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, certmanager.CertificateRequestReasonPending, fmt.Sprintf("Failed to retrieve Issuer resource %s: %v", issNamespaceName, err))

			// sleep 1 second if it fails
			time.Sleep(1 * time.Second)
			return reconcile.Result{}, err
		}

		if !issuerHasCondition(iss, api.IssuerCondition{Type: api.ConditionReady, Status: api.ConditionTrue}) {
			err := fmt.Errorf("resource %s is not ready", issNamespaceName)
			log.Error(err, "issuer failed readiness checks", "namespace", issNamespaceName.Namespace, "name", issNamespaceName.Name)
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, certmanager.CertificateRequestReasonPending, fmt.Sprintf("Issuer %s is not Ready", issNamespaceName))

			return reconcile.Result{}, err
		}
	} else if cr.Spec.IssuerRef.Kind == "ClusterIssuer" {
		issNamespaceName = types.NamespacedName{
			Namespace: "",
			Name:      cr.Spec.IssuerRef.Name,
		}
	}

	log.WithValues("issuer", issNamespaceName).Info("process")

	// Load the provisioner that will sign the CertificateRequest
	p, ok := provisioners.Load(issNamespaceName)

	if !ok {
		err := fmt.Errorf("provisioner %s not found", issNamespaceName)
		log.Error(err, "failed to provisioner for Issuer resource")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, certmanager.CertificateRequestReasonPending, fmt.Sprintf("Failed to load provisioner for Issuer resource %s", issNamespaceName))

		// sleep 1 second if it fails
		time.Sleep(1 * time.Second)

		return reconcile.Result{}, err
	}

	cert, ca, err := p.Sign(ctx, cr)
	if err != nil {
		log.Error(err, "failed to sign certificate request")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, certmanager.CertificateRequestReasonFailed, fmt.Sprintf("Failed to sign certificate request: %v", err))

		return reconcile.Result{}, err
	}

	cr.Status.Certificate = cert
	cr.Status.CA = ca
	_ = r.setStatus(ctx, cr, cmmeta.ConditionTrue, certmanager.CertificateRequestReasonIssued, "Certificate issued")

	return reconcile.Result{}, nil
}

// setStatus is a helper function to set the CertifcateRequest status condition with reason and message, and update the API.
func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *certmanager.CertificateRequest, status cmmeta.ConditionStatus, reason, message string) error {
	cmutil.SetCertificateRequestCondition(cr, certmanager.CertificateRequestConditionReady, status, reason, message)

	return r.Client.Status().Update(ctx, cr)
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanager.CertificateRequest{}).
		Complete(r)
}

// issuerHasCondition will return true if the given Issuer resource has
// a condition matching the provided IssuerCondition. Only the Type and
// Status field will be used in the comparison, meaning that this function will
// return 'true' even if the Reason, Message and LastTransitionTime fields do
// not match.
func issuerHasCondition(iss api.Issuer, c api.IssuerCondition) bool {
	existingConditions := iss.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}
