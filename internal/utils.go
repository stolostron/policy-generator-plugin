// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/kustomize/api/krusty"
	kustomizetypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	"open-cluster-management.io/policy-generator-plugin/internal/expanders"
	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

// getManifests will get all of the manifest files associated with the input policy configuration
// separated by policyConf.Manifests entries. An error is returned if a manifest path cannot
// be read.
func getManifests(policyConf *types.PolicyConfig) ([][]map[string]interface{}, error) {
	manifests := [][]map[string]interface{}{}
	hasKustomize := map[string]bool{}

	for _, manifest := range policyConf.Manifests {
		manifestPaths := []string{}
		manifestFiles := []map[string]interface{}{}
		readErr := fmt.Errorf("failed to read the manifest path %s", manifest.Path)

		manifestPathInfo, err := os.Stat(manifest.Path)
		if err != nil {
			return nil, readErr
		}

		resolvedFiles := []string{}

		if manifestPathInfo.IsDir() {
			files, err := os.ReadDir(manifest.Path)
			if err != nil {
				return nil, readErr
			}

			for _, f := range files {
				if f.IsDir() {
					continue
				}

				filepath := f.Name()
				ext := path.Ext(filepath)

				if ext != ".yaml" && ext != ".yml" {
					continue
				}
				// Handle when a Kustomization directory is specified
				_, filename := path.Split(filepath)
				if filename == "kustomization.yml" || filename == "kustomization.yaml" {
					hasKustomize[manifest.Path] = true
					resolvedFiles = []string{manifest.Path}

					break
				}

				yamlPath := path.Join(manifest.Path, f.Name())
				resolvedFiles = append(resolvedFiles, yamlPath)
			}

			manifestPaths = append(manifestPaths, resolvedFiles...)
		} else {
			// Unmarshal the manifest in order to check for metadata patch replacement
			manifestFile, err := unmarshalManifestFile(manifest.Path)
			if err != nil {
				return nil, err
			}

			if len(manifestFile) == 0 {
				return nil, fmt.Errorf("found empty YAML in the manifest at %s", manifest.Path)
			}
			// Allowing replace the original manifest metadata.name and/or metadata.namespace if it is a single
			// yaml structure in the manifest path
			if len(manifestFile) == 1 && len(manifest.Patches) == 1 {
				if patchMetadata, ok := manifest.Patches[0]["metadata"].(map[string]interface{}); ok {
					if metadata, ok := manifestFile[0]["metadata"].(map[string]interface{}); ok {
						name, ok := patchMetadata["name"].(string)
						if ok && name != "" {
							metadata["name"] = name
						}

						namespace, ok := patchMetadata["namespace"].(string)
						if ok && namespace != "" {
							metadata["namespace"] = namespace
						}

						manifestFile[0]["metadata"] = metadata
					}
				}
			}

			manifestFiles = append(manifestFiles, manifestFile...)
		}

		for _, manifestPath := range manifestPaths {
			var manifestFile []map[string]interface{}
			var err error

			if hasKustomize[manifestPath] {
				manifestFile, err = processKustomizeDir(manifestPath)
			} else {
				manifestFile, err = unmarshalManifestFile(manifestPath)
			}

			if err != nil {
				return nil, err
			}

			if len(manifestFile) == 0 {
				continue
			}

			manifestFiles = append(manifestFiles, manifestFile...)
		}

		if len(manifest.Patches) > 0 {
			patcher := manifestPatcher{manifests: manifestFiles, patches: manifest.Patches, openAPI: manifest.OpenAPI}
			const errTemplate = `failed to process the manifest at "%s": %w`

			err = patcher.Validate()
			if err != nil {
				return nil, fmt.Errorf(errTemplate, manifest.Path, err)
			}

			patchedFiles, err := patcher.ApplyPatches()
			if err != nil {
				return nil, fmt.Errorf(errTemplate, manifest.Path, err)
			}

			manifestFiles = patchedFiles
		}

		manifests = append(manifests, manifestFiles)
	}

	return manifests, nil
}

// getPolicyTemplates generates the policy templates for the ConfigurationPolicy manifests
// policyConf.ConsolidateManifests = true (default value) will generate a policy templates slice
// that just has one template which includes all the manifests specified in policyConf.
// policyConf.ConsolidateManifests = false will generate a policy templates slice
// that each template includes a single manifest specified in policyConf.
// An error is returned if one or more manifests cannot be read or are invalid.
func getPolicyTemplates(policyConf *types.PolicyConfig) ([]map[string]interface{}, error) {
	manifestGroups, err := getManifests(policyConf)
	if err != nil {
		return nil, err
	}

	objectTemplatesLength := len(manifestGroups)
	policyTemplatesLength := 1

	if !policyConf.ConsolidateManifests {
		policyTemplatesLength = len(manifestGroups)
		objectTemplatesLength = 0
	}

	objectTemplates := make([]map[string]interface{}, 0, objectTemplatesLength)
	policyTemplates := make([]map[string]interface{}, 0, policyTemplatesLength)

	var consolidatedPolicyName string

	policyNameCounter := map[string]int{}

	for i, manifestGroup := range manifestGroups {
		complianceType := policyConf.Manifests[i].ComplianceType
		metadataComplianceType := policyConf.Manifests[i].MetadataComplianceType
		recreateOption := policyConf.Manifests[i].RecreateOption
		recordDiff := policyConf.Manifests[i].RecordDiff
		ignorePending := policyConf.Manifests[i].IgnorePending
		extraDeps := policyConf.Manifests[i].ExtraDependencies
		objSelector := policyConf.Manifests[i].ObjectSelector

		policyName := policyConf.Manifests[i].Name
		if policyName == "" {
			policyName = policyConf.Name
		}

		for _, manifest := range manifestGroup {
			err := setGatekeeperEnforcementAction(manifest,
				policyConf.Manifests[i].GatekeeperEnforcementAction)
			if err != nil {
				return nil, fmt.Errorf("err in setting constraint.spec.enforcementAction has "+
					"an error %w in manifest index: %v", err, i)
			}

			isPolicyTypeManifest, isOcmPolicy, err := isPolicyTypeManifest(
				manifest, policyConf.InformGatekeeperPolicies)
			if err != nil {
				return nil, fmt.Errorf(
					"%w in manifest path: %s",
					err,
					policyConf.Manifests[i].Path,
				)
			}

			if isPolicyTypeManifest {
				var policyTemplate map[string]interface{}

				_, found, _ := unstructured.NestedString(manifest, "object-templates-raw")
				if found {
					policyNameCounter[policyName]++
					policyTemplate = buildPolicyTemplate(
						policyConf,
						manifest["object-templates-raw"],
						&policyConf.Manifests[i].ConfigurationPolicyOptions,
						getConfigurationPolicyName(policyName, policyNameCounter[policyName]),
					)
				} else {
					policyTemplate = map[string]interface{}{"objectDefinition": manifest}
				}

				// Only set dependency options if it's an OCM policy
				if isOcmPolicy {
					// Remove any namespace specified in the OCM policy since that would be invalid
					unstructured.RemoveNestedField(manifest, "metadata", "namespace")

					setTemplateOptions(policyTemplate, ignorePending, extraDeps)
				} else {
					policyTemplateUnstructured := unstructured.Unstructured{Object: manifest}

					annotations := policyTemplateUnstructured.GetAnnotations()
					if annotations == nil {
						annotations = make(map[string]string, 1)
					}

					annotations[severityAnnotation] = policyConf.Severity

					policyTemplateUnstructured.SetAnnotations(annotations)
				}

				policyTemplates = append(policyTemplates, policyTemplate)

				continue
			}

			objTemplate := map[string]interface{}{
				"complianceType":   complianceType,
				"objectDefinition": manifest,
			}

			if metadataComplianceType != "" {
				objTemplate["metadataComplianceType"] = metadataComplianceType
			}

			if !objSelector.IsUnset() {
				objTemplate["objectSelector"] = objSelector
			}

			if recreateOption != "" {
				objTemplate["recreateOption"] = recreateOption
			}

			if recordDiff != "" {
				objTemplate["recordDiff"] = recordDiff
			}

			if policyConf.ConsolidateManifests {
				if consolidatedPolicyName == "" {
					consolidatedPolicyName = policyConf.Manifests[i].Name
				}
				// put all objTemplate with manifest into single consolidated objectTemplates
				objectTemplates = append(objectTemplates, objTemplate)
			} else {
				policyNameCounter[policyName]++
				// casting each objTemplate with manifest to objectTemplates type
				// build policyTemplate for each objectTemplates
				policyTemplate := buildPolicyTemplate(
					policyConf,
					[]map[string]interface{}{objTemplate},
					&policyConf.Manifests[i].ConfigurationPolicyOptions,
					getConfigurationPolicyName(policyName, policyNameCounter[policyName]),
				)

				setTemplateOptions(policyTemplate, ignorePending, extraDeps)

				policyTemplates = append(policyTemplates, policyTemplate)
			}
		}
	}

	if len(policyTemplates) == 0 && len(objectTemplates) == 0 {
		return nil, fmt.Errorf(
			"the policy %s must specify at least one non-empty manifest file", policyConf.Name,
		)
	}

	// just build one policyTemplate by using the above non-empty consolidated objectTemplates
	// ConsolidateManifests = true or there is non-policy-type manifest
	if policyConf.ConsolidateManifests && len(objectTemplates) > 0 {
		if consolidatedPolicyName == "" {
			consolidatedPolicyName = policyConf.Name
		}

		policyNameCounter[consolidatedPolicyName]++
		// If ConsolidateManifests is true and multiple manifest[].names are provided, the configuration policy
		// name will be the first name of manifest[].names
		policyTemplate := buildPolicyTemplate(
			policyConf,
			objectTemplates,
			&policyConf.ConfigurationPolicyOptions,
			getConfigurationPolicyName(consolidatedPolicyName, policyNameCounter[consolidatedPolicyName]),
		)
		setTemplateOptions(policyTemplate, policyConf.IgnorePending, policyConf.ExtraDependencies)
		policyTemplates = append(policyTemplates, policyTemplate)
	}

	// check the enabled expanders and add additional policy templates
	for i, manifestGroup := range manifestGroups {
		ignorePending := policyConf.Manifests[i].IgnorePending
		extraDeps := policyConf.Manifests[i].ExtraDependencies

		for _, additionalTemplate := range handleExpanders(manifestGroup, *policyConf) {
			setTemplateOptions(additionalTemplate, ignorePending, extraDeps)
			policyTemplates = append(policyTemplates, additionalTemplate)
		}
	}

	// order manifests now that everything is defined
	if policyConf.OrderManifests {
		previousTemplate := types.PolicyDependency{Compliance: "Compliant"}

		for i, tmpl := range policyTemplates {
			if previousTemplate.Name != "" {
				policyTemplates[i]["extraDependencies"] = []types.PolicyDependency{previousTemplate}
			}

			// these fields are known to exist since the plugin created them
			previousTemplate.Name, _, _ = unstructured.NestedString(tmpl, "objectDefinition", "metadata", "name")
			previousTemplate.APIVersion, _, _ = unstructured.NestedString(tmpl, "objectDefinition", "apiVersion")
			previousTemplate.Kind, _, _ = unstructured.NestedString(tmpl, "objectDefinition", "kind")
		}
	}

	return policyTemplates, nil
}

func getConfigurationPolicyName(name string, count int) string {
	if count > 1 {
		return fmt.Sprintf("%s%d", name, count)
	}

	return name
}

// setGatekeeperEnforcementAction function override gatekeeper.constraint.enforcementAction
func setGatekeeperEnforcementAction(manifest map[string]interface{}, enforcementAction string) error {
	if enforcementAction == "" {
		return nil
	}

	apiVersion, _, _ := unstructured.NestedString(manifest, "apiVersion")

	if strings.HasPrefix(apiVersion, "constraints.gatekeeper.sh") {
		err := unstructured.SetNestedField(manifest, enforcementAction, "spec", "enforcementAction")
		if err != nil {
			return err
		}
	}

	return nil
}

func setTemplateOptions(tmpl map[string]interface{}, ignorePending bool, extraDeps []types.PolicyDependency) {
	if ignorePending {
		tmpl["ignorePending"] = ignorePending
	}

	if len(extraDeps) > 0 {
		tmpl["extraDependencies"] = extraDeps
	}
}

// isPolicyTypeManifest determines whether the manifest is a kind handled by the generator and
// whether the manifest is a non-root OCM policy manifest by checking apiVersion and kind fields.
// Return error when:
// - apiVersion and kind fields can't be determined
// - the manifest is a root policy manifest
// - the manifest is invalid because it is missing a name
func isPolicyTypeManifest(manifest map[string]interface{}, informGatekeeperPolicies bool) (bool, bool, error) {
	// check for object-templates-raw separate from policies since they have separate requirements
	_, found, _ := unstructured.NestedString(manifest, "object-templates-raw")
	if found {
		// return true for isPolicyType, since object-templates-raw is in a ConfigurationPolicy
		return true, true, nil
	}

	apiVersion, found, err := unstructured.NestedString(manifest, "apiVersion")
	if !found || err != nil {
		return false, false, errors.New("invalid or not found apiVersion")
	}

	kind, found, err := unstructured.NestedString(manifest, "kind")
	if !found || err != nil {
		return false, false, errors.New("invalid or not found kind")
	}

	// Don't allow generation for root Policies
	isOcmAPI := strings.HasPrefix(apiVersion, "policy.open-cluster-management.io")
	if isOcmAPI && kind == "Policy" {
		return false, false, errors.New("providing a root Policy kind is not supported by the generator; " +
			"the manifest should be applied to the hub cluster directly")
	}

	// Identify OCM Policies
	isOcmPolicy := isOcmAPI && kind != "Policy" && strings.HasSuffix(kind, "Policy")

	// Identify Gatekeeper kinds
	isGkConstraintTemplate := strings.HasPrefix(apiVersion, "templates.gatekeeper.sh") && kind == "ConstraintTemplate"
	isGkConstraint := strings.HasPrefix(apiVersion, "constraints.gatekeeper.sh")
	isGkObj := isGkConstraintTemplate || isGkConstraint

	isPolicy := isOcmPolicy || (isGkObj && !informGatekeeperPolicies)

	if isPolicy {
		// metadata.name is required on policy manifests
		_, found, err = unstructured.NestedString(manifest, "metadata", "name")
		if !found || err != nil {
			return isPolicy, isOcmPolicy, errors.New("invalid or not found metadata.name")
		}
	}

	return isPolicy, isOcmPolicy, nil
}

// setNamespaceSelector sets the namespace selector, if set, on the input policy template.
func setNamespaceSelector(
	policyConf *types.ConfigurationPolicyOptions,
	policyTemplate map[string]interface{},
) {
	selector := policyConf.NamespaceSelector
	if selector.Exclude != nil ||
		selector.Include != nil ||
		selector.MatchLabels != nil ||
		selector.MatchExpressions != nil {
		objDef := policyTemplate["objectDefinition"].(map[string]interface{})
		spec := objDef["spec"].(map[string]interface{})
		spec["namespaceSelector"] = selector
	}
}

// processKustomizeDir runs a provided directory through Kustomize in order to generate the manifests within it.
func processKustomizeDir(path string) ([]map[string]interface{}, error) {
	kustomizeOpts := krusty.MakeDefaultOptions()

	if os.Getenv("POLICY_GEN_ENABLE_HELM") == "true" {
		kustomizeOpts.PluginConfig.HelmConfig.Enabled = true
		kustomizeOpts.PluginConfig.HelmConfig.Command = "helm"
	}

	if os.Getenv("POLICY_GEN_DISABLE_LOAD_RESTRICTORS") == "true" {
		kustomizeOpts.LoadRestrictions = kustomizetypes.LoadRestrictionsNone
	}

	k := krusty.MakeKustomizer(kustomizeOpts)

	resourceMap, err := k.Run(filesys.MakeFsOnDisk(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to process provided kustomize directory '%s': %w", path, err)
	}

	manifestsYAML, err := resourceMap.AsYaml()
	if err != nil {
		return nil, fmt.Errorf("failed to convert the kustomize manifest(s) to YAML from directory '%s': %w", path, err)
	}

	manifests, err := unmarshalManifestBytes(manifestsYAML)
	if err != nil {
		return nil, fmt.Errorf("failed to read the kustomize manifest(s) from directory '%s': %w", path, err)
	}

	return manifests, nil
}

// buildPolicyTemplate generates single policy template by using objectTemplates with manifests.
// policyNum defines which number the configuration policy is in the policy. If it is greater than
// one then the configuration policy name will have policyNum appended to it.
func buildPolicyTemplate(
	policyConf *types.PolicyConfig,
	objectTemplates interface{},
	configPolicyOptionsOverrides *types.ConfigurationPolicyOptions,
	configPolicyName string,
) map[string]interface{} {
	policySpec := map[string]interface{}{
		"remediationAction": policyConf.RemediationAction,
		"severity":          policyConf.Severity,
	}

	switch objectTemplates.(type) {
	case string:
		policySpec["object-templates-raw"] = objectTemplates
	case []map[string]interface{}:
		policySpec["object-templates"] = objectTemplates
	}

	policyTemplate := map[string]interface{}{
		"objectDefinition": map[string]interface{}{
			"apiVersion": policyAPIVersion,
			"kind":       configPolicyKind,
			"metadata": map[string]interface{}{
				"name": configPolicyName,
			},
			"spec": policySpec,
		},
	}

	// Set NamespaceSelector with policy configuration
	setNamespaceSelector(&policyConf.ConfigurationPolicyOptions, policyTemplate)

	if len(policyConf.ConfigurationPolicyAnnotations) > 0 {
		objDef := policyTemplate["objectDefinition"].(map[string]interface{})
		metadata := objDef["metadata"].(map[string]interface{})
		metadata["annotations"] = policyConf.ConfigurationPolicyAnnotations
	}

	objDef := policyTemplate["objectDefinition"].(map[string]interface{})
	configSpec := objDef["spec"].(map[string]interface{})

	// Set EvaluationInterval with manifest overrides
	evaluationInterval := configPolicyOptionsOverrides.EvaluationInterval
	if evaluationInterval.Compliant != "" || evaluationInterval.NonCompliant != "" {
		evalInterval := map[string]interface{}{}

		if evaluationInterval.Compliant != "" {
			evalInterval["compliant"] = evaluationInterval.Compliant
		}

		if evaluationInterval.NonCompliant != "" {
			evalInterval["noncompliant"] = evaluationInterval.NonCompliant
		}

		configSpec["evaluationInterval"] = evalInterval
	}

	// Set customMessage with manifest overrides
	customMessage := configPolicyOptionsOverrides.CustomMessage
	if customMessage.Compliant != "" || customMessage.NonCompliant != "" {
		customMessageJSON := map[string]interface{}{}

		if customMessage.Compliant != "" {
			customMessageJSON["compliant"] = customMessage.Compliant
		}

		if customMessage.NonCompliant != "" {
			customMessageJSON["noncompliant"] = customMessage.NonCompliant
		}

		configSpec["customMessage"] = customMessageJSON
	}

	// Set NamespaceSelector with manifest overrides
	setNamespaceSelector(configPolicyOptionsOverrides, policyTemplate)

	// Set PruneObjectBehavior with manifest overrides
	if configPolicyOptionsOverrides.PruneObjectBehavior != "" {
		configSpec["pruneObjectBehavior"] = configPolicyOptionsOverrides.PruneObjectBehavior
	}

	// Set RemediationAction with manifest overrides
	if configPolicyOptionsOverrides.RemediationAction != "" {
		configSpec["remediationAction"] = configPolicyOptionsOverrides.RemediationAction
	}

	// Set Severity with manifest overrides
	if configPolicyOptionsOverrides.Severity != "" {
		configSpec["severity"] = configPolicyOptionsOverrides.Severity
	}

	return policyTemplate
}

// handleExpanders will go through all the enabled expanders and generate additional
// policy templates to include in the policy.
func handleExpanders(manifests []map[string]interface{}, policyConf types.PolicyConfig) []map[string]interface{} {
	policyTemplates := []map[string]interface{}{}

	for _, expander := range expanders.GetExpanders() {
		for _, m := range manifests {
			if expander.Enabled(&policyConf) && expander.CanHandle(m) {
				expandedPolicyTemplates := expander.Expand(m, policyConf.Severity)
				policyTemplates = append(policyTemplates, expandedPolicyTemplates...)
			}
		}
	}

	return policyTemplates
}

// unmarshalManifestFile unmarshals the input object manifest/definition file into
// a slice in order to account for multiple YAML documents in the same file.
// If the file cannot be decoded or each document is not a map, an error will
// be returned.
func unmarshalManifestFile(manifestPath string) ([]map[string]interface{}, error) {
	// #nosec G304
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the manifest file %s", manifestPath)
	}

	rv, err := unmarshalManifestBytes(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the manifest file at %s: %w", manifestPath, err)
	}

	return rv, nil
}

// unmarshalManifestBytes unmarshals the input bytes slice of an object manifest/definition file
// into a slice of maps in order to account for multiple YAML documents in the bytes slice. If each
// document is not a map, an error will be returned.
func unmarshalManifestBytes(manifestBytes []byte) ([]map[string]interface{}, error) {
	yamlDocs := []map[string]interface{}{}
	d := yaml.NewDecoder(bytes.NewReader(manifestBytes))

	for {
		var obj interface{}

		err := d.Decode(&obj)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			//nolint:wrapcheck
			return nil, err
		}

		if _, ok := obj.(map[string]interface{}); !ok && obj != nil {
			err := errors.New("the input manifests must be in the format of YAML objects")

			return nil, err
		}

		if obj != nil {
			yamlDocs = append(yamlDocs, obj.(map[string]interface{}))
		}
	}

	return yamlDocs, nil
}

// verifyFilePath verifies that the file path is in the directory tree under baseDirectory.
// An error is returned if it is not or the paths couldn't be properly resolved.
func verifyFilePath(baseDirectory string, filePath, fileType string) error {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("could not resolve the %s path %s to an absolute path", fileType, filePath)
	}

	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return fmt.Errorf("could not resolve symlinks to the %s path %s", fileType, filePath)
	}

	relPath, err := filepath.Rel(baseDirectory, absPath)
	if err != nil {
		return fmt.Errorf(
			"could not resolve the %s path %s to a relative path from the kustomization.yaml file",
			fileType, filePath,
		)
	}

	if relPath == "." {
		return fmt.Errorf(
			"the %s path %s may not refer to the same directory as the kustomization.yaml file",
			fileType, filePath,
		)
	}

	parDir := ".." + string(filepath.Separator)
	if strings.HasPrefix(relPath, parDir) || relPath == ".." {
		return fmt.Errorf(
			"the %s path %s is not in the same directory tree as the kustomization.yaml file",
			fileType, filePath,
		)
	}

	return nil
}

// Check policy-templates to see if all the remediation actions match, if so return the root policy remediation action
func getRootRemediationAction(policyTemplates []map[string]interface{}) string {
	var action string

	for _, value := range policyTemplates {
		objDef := value["objectDefinition"].(map[string]interface{})
		if spec, ok := objDef["spec"].(map[string]interface{}); ok {
			if _, ok = spec["remediationAction"].(string); ok {
				if action == "" {
					action = spec["remediationAction"].(string)
				} else if spec["remediationAction"].(string) != action {
					return ""
				}
			}
		}
	}

	// "InformOnly" should only apply to ConfigurationPolicies
	if strings.EqualFold(action, "informonly") {
		action = "inform"
	}

	return action
}
