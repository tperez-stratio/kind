/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package createworker

import (
	"os"

	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kind/pkg/commons"
)

type KEOSDescriptor struct {
	ExternalRegistry struct {
		AuthRequired bool   `yaml:"auth_required"`
		Type         string `yaml:"type"`
		URL          string `yaml:"url"`
	} `yaml:"external_registry"`
	AWS struct {
		Enabled bool `yaml:"enabled"`
		EKS     bool `yaml:"eks"`
	} `yaml:"aws,omitempty"`
	GCP struct {
		Enabled bool `yaml:"enabled"`
		GKE     bool `yaml:"gke"`
	} `yaml:"gcp,omitempty"`
	Keos struct {
		Calico struct {
			Ipip                 bool   `yaml:"ipip"`
			Pool                 string `yaml:"pool"`
			DeployTigeraOperator bool   `yaml:"deploy_tigera_operator"`
		} `yaml:"calico,omitempty"`
		ClusterID       string `yaml:"cluster_id"`
		Domain          string `yaml:"domain"`
		Flavour         string `yaml:"flavour"`
		K8sInstallation bool   `yaml:"k8s_installation"`
		Storage         struct {
			DefaultStorageClass string   `yaml:"default_storage_class"`
			Providers           []string `yaml:"providers"`
		} `yaml:"storage"`
	} `yaml:"keos"`
}

func createKEOSDescriptor(descriptorFile commons.DescriptorFile, storageClass string) error {

	var keosDescriptor KEOSDescriptor
	var err error

	// External registry
	for _, registry := range descriptorFile.DockerRegistries {
		if registry.KeosRegistry {
			keosDescriptor.ExternalRegistry.URL = registry.URL
			keosDescriptor.ExternalRegistry.AuthRequired = registry.AuthRequired
			keosDescriptor.ExternalRegistry.Type = registry.Type
		}
	}

	// AWS
	if descriptorFile.InfraProvider == "aws" {
		keosDescriptor.AWS.Enabled = true
		keosDescriptor.AWS.EKS = descriptorFile.ControlPlane.Managed
	}

	// GCP
	if descriptorFile.InfraProvider == "gcp" {
		keosDescriptor.GCP.Enabled = true
		keosDescriptor.GCP.GKE = descriptorFile.ControlPlane.Managed
	}

	// Keos
	keosDescriptor.Keos.ClusterID = descriptorFile.ClusterID
	keosDescriptor.Keos.K8sInstallation = false
	keosDescriptor.Keos.Domain = descriptorFile.Keos.Domain
	keosDescriptor.Keos.Flavour = descriptorFile.Keos.Flavour

	// Keos - Calico
	if !descriptorFile.ControlPlane.Managed {
		keosDescriptor.Keos.Calico.Ipip = true
		keosDescriptor.Keos.Calico.Pool = "192.168.0.0/16"
		keosDescriptor.Keos.Calico.DeployTigeraOperator = true
	}

	// Keos - Storage
	keosDescriptor.Keos.Storage.DefaultStorageClass = storageClass
	keosDescriptor.Keos.Storage.Providers = []string{"custom"}

	keosYAMLData, err := yaml.Marshal(keosDescriptor)
	if err != nil {
		return err
	}

	// Write file to disk
	err = os.WriteFile("keos.yaml", []byte(keosYAMLData), 0644)
	if err != nil {
		return err
	}

	return nil
}
