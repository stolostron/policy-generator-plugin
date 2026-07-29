package expanders

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

type KyvernoPolicyExpander struct{}

const (
	kyvernoAPIVersion             = "kyverno.io/v1"
	kyvernoClusterKind            = "ClusterPolicy"
	kyvernoPolicyReportAPIVersion = "wgpolicyk8s.io/v1alpha2"
	kyvernoNamespacedKind         = "Policy"
)

// CanHandle determines if the manifest is a Kyverno policy that can be expanded.
func (k KyvernoPolicyExpander) CanHandle(manifest map[string]any) bool {
	if a, _, _ := unstructured.NestedString(manifest, "apiVersion"); a != kyvernoAPIVersion {
		return false
	}

	kind, _, _ := unstructured.NestedString(manifest, "kind")
	if kind != kyvernoClusterKind && kind != kyvernoNamespacedKind {
		return false
	}

	if n, _, _ := unstructured.NestedString(manifest, "metadata", "name"); n == "" {
		return false
	}

	return true
}

// Enabled determines if the policy configuration allows a Kyverno policy to be expanded.
func (k KyvernoPolicyExpander) Enabled(policyConf *types.PolicyConfig) bool {
	return policyConf.InformKyvernoPolicies
}

// Expand will generate additional policy templates for the Kyverno policy for auditing purposes
// through Open Cluster Management. This should be run after the CanHandle method.
func (k KyvernoPolicyExpander) Expand(
	manifest map[string]any, severity string,
) []map[string]any {
	templates := []map[string]any{}
	// This was previously validated in the CanHandle method.
	policyName, _, _ := unstructured.NestedString(manifest, "metadata", "name")

	configPolicyName := "inform-kyverno-" + policyName
	configurationPolicy := map[string]any{
		"objectDefinition": map[string]any{
			"apiVersion": configPolicyAPIVersion,
			"kind":       configPolicyKind,
			"metadata":   map[string]any{"name": configPolicyName},
			"spec": map[string]any{
				"namespaceSelector": map[string]any{
					"exclude": []string{"kube-*"},
					"include": []string{"*"},
				},
				"remediationAction": "inform",
				"severity":          severity,
				"object-templates": []map[string]any{
					{
						"complianceType": "mustnothave",
						"objectDefinition": map[string]any{
							"apiVersion": kyvernoPolicyReportAPIVersion,
							"kind":       kyvernoClusterKind + "Report",
							"results": []map[string]any{
								{
									"policy": policyName,
									"result": "fail",
								},
							},
						},
					},
					{
						"complianceType": "mustnothave",
						"objectDefinition": map[string]any{
							"apiVersion": kyvernoPolicyReportAPIVersion,
							"kind":       kyvernoNamespacedKind + "Report",
							"results": []map[string]any{
								{
									"policy": policyName,
									"result": "fail",
								},
							},
						},
					},
				},
			},
		},
	}

	templates = append(templates, configurationPolicy)

	return templates
}
