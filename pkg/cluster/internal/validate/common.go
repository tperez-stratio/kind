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

package validate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

const (
	MaxWorkerNodeNameLength = 25
	MinWorkerNodeNameLength = 3
)

var k8sVersionSupported = []string{"1.24", "1.25", "1.26", "1.27", "1.28"}

func validateCommon(spec commons.KeosSpec, clusterConfigSpec commons.ClusterConfigSpec) error {
	var err error
	if err = validateK8SVersion(spec.K8SVersion); err != nil {
		return err
	}
	if err = validateWorkers(spec.WorkerNodes); err != nil {
		return err
	}
	if err = validateVolumes(spec); err != nil {
		return err
	}
	if err = validateClusterConfig(spec, clusterConfigSpec); err != nil {
		return err
	}
	return nil
}

func validateClusterConfig(spec commons.KeosSpec, clusterConfigSpec commons.ClusterConfigSpec) error {
	if spec.ControlPlane.Managed {
		if clusterConfigSpec.ControlplaneConfig.MaxUnhealthy != nil {
			return errors.New("spec: Invalid value: \"controlplane_config.max_unhealthy\" in clusterConfig: This field cannot be set with managed cluster")
		}
	}
	return nil
}

func validateK8SVersion(v string) error {
	var isVersion = regexp.MustCompile(`^v\d.\d{2}.\d{1,2}(-gke.\d{3,4})?$`).MatchString
	if !isVersion(v) {
		return errors.New("spec: Invalid value: \"k8s_version\": regex used for validation is '^v\\d.\\d{2}.\\d{1,2}(-gke.\\d{3,4})?$'")
	}
	K8sVersionMM := strings.Split(v, ".")
	k8sVersion := strings.Join(K8sVersionMM[:2], ".")
	if !slices.Contains(k8sVersionSupported, strings.ReplaceAll(k8sVersion, "v", "")) {
		return errors.New("spec: Invalid value: \"k8s_version\": kubernetes versions supported: " + fmt.Sprint(strings.Join(k8sVersionSupported, ", ")))
	}
	return nil
}

func validateWorkers(wn commons.WorkerNodes) error {
	if err := validateWorkersName(wn); err != nil {
		return err
	}
	if err := validateWorkersQuantity(wn); err != nil {
		return err
	}
	if err := validateWorkersTaints(wn); err != nil {
		return err
	}
	if err := validateWorkersType(wn); err != nil {
		return err
	}
	return nil
}

func validateWorkersName(workerNodes commons.WorkerNodes) error {
	regex := regexp.MustCompile(`^[-a-z]([-a-z0-9]*[a-z0-9])+$`)
	for i, worker := range workerNodes {
		// Validate worker name
		if !regex.MatchString(worker.Name) {
			return errors.New(worker.Name + " is invalid: " +
				"must consist of lower case alphanumeric characters, '-' or '.', start with an alphabetic character and end with an alphanumeric character, " +
				"regex used for validation is '" + regex.String() + "'")
		}
		// Validate worker name length
		if len([]rune(worker.Name)) > MaxWorkerNodeNameLength || len([]rune(worker.Name)) < MinWorkerNodeNameLength {
			return errors.New(worker.Name + " is invalid: must be no more than " +
				strconv.Itoa(MaxWorkerNodeNameLength) + " & no less than " +
				strconv.Itoa(MinWorkerNodeNameLength) + " characters long",
			)
		}
		// Validate worker name uniqueness
		for j, worker2 := range workerNodes {
			if i != j && worker.Name == worker2.Name {
				return errors.New("WorkerNodes name " + worker.Name + " is duplicated")
			}
		}
	}
	return nil
}

func validateWorkersQuantity(workerNodes commons.WorkerNodes) error {
	var InitialBalancedWorkerNode int
	var InitialUnBalancedWorkerNode int
	numberOfNodes := len(workerNodes)

	for _, wn := range workerNodes {
		var isBalanced = wn.ZoneDistribution == "balanced" || (wn.ZoneDistribution == "" && wn.AZ == "")

		// Cluster Autoscaler doesn't scale a managed node group lower than minSize or higher than maxSize.
		if wn.NodeGroupMaxSize < *wn.Quantity && wn.NodeGroupMaxSize != 0 {
			return errors.New("max_size in WorkerNodes " + wn.Name + " must be equal or greater than quantity")
		}
		if wn.NodeGroupMinSize != nil && (*wn.Quantity < *wn.NodeGroupMinSize) {
			return errors.New("quantity in WorkerNodes " + wn.Name + " must be equal or greater than min_size")
		}
		if wn.AZ != "" && wn.ZoneDistribution != "" {
			return errors.New("az and zone_distribution cannot be used at the same time for " + wn.Name)
		}
		if isBalanced && *wn.Quantity%3 != 0 {
			return errors.New("quantity in WorkerNode: " + wn.Name + " must be zero or multiple of 3")
		}

		// Validate when only one WorkerNode is defined
		if numberOfNodes == 1 {
			switch {
			case isBalanced && (*wn.Quantity == 0 || *wn.Quantity%3 != 0):
				return errors.New("in case of defining one WorkerNode, quantity must be multiple of 3 for " + wn.Name)
			case !isBalanced && *wn.Quantity < 1:
				return errors.New("in case of defining one WorkerNode, quantity must be greater than 0 for " + wn.Name)
			default:
				if isBalanced {
					InitialBalancedWorkerNode++
				} else {
					InitialUnBalancedWorkerNode++
				}
			}
		} else if numberOfNodes > 1 && *wn.Quantity > 0 {
			if isBalanced && *wn.Quantity%3 == 0 {
				InitialBalancedWorkerNode++
			} else if !isBalanced {
				InitialUnBalancedWorkerNode++
			}
		}
	}

	if InitialBalancedWorkerNode == 0 && InitialUnBalancedWorkerNode == 0 {
		return errors.New("at least one WorkerNode must have quantity equal or greater than 1 for unbalanced and greater than 0 and multiple of 3 for balanced")
	}

	return nil
}

func validateWorkersTaints(wns commons.WorkerNodes) error {
	regex := regexp.MustCompile(`^(\w+|.*)=(\w+|.*):(NoSchedule|PreferNoSchedule|NoExecute)$`)
	for _, wn := range wns {
		for i, taint := range wn.Taints {
			if !regex.MatchString(taint) {
				return errors.New("Incorrect taint format in taint[" + strconv.Itoa(i) + "] of wn: " + wn.Name + "")
			}
		}
	}
	return nil
}

func validateWorkersType(wns commons.WorkerNodes) error {
	hasNodeSystem := false
	for _, wn := range wns {
		if len(wn.Taints) == 0 && !wn.Spot {
			hasNodeSystem = true
		}
	}
	if !hasNodeSystem {
		return errors.New("at least one worker node must be non spot and without taints")
	}
	return nil
}

func validateVolumes(spec commons.KeosSpec) error {
	if !spec.ControlPlane.Managed {
		for i, ev := range spec.ControlPlane.ExtraVolumes {
			for _, ev2 := range spec.ControlPlane.ExtraVolumes[i+1:] {
				if ev.Label == ev2.Label {
					return errors.New("spec.control_plane.extra_volumes[" + strconv.Itoa(i) + "]: Invalid value: \"label\": is duplicated")
				}
				if ev.MountPath == ev2.MountPath {
					return errors.New("spec.control_plane.extra_volumes[" + strconv.Itoa(i) + "]: Invalid value: \"mount_path\": is duplicated")
				}
			}
		}
	}
	for _, wn := range spec.WorkerNodes {
		for i, ev := range wn.ExtraVolumes {
			for _, ev2 := range wn.ExtraVolumes[i+1:] {
				if ev.Label == ev2.Label {
					return errors.New("spec.worker_nodes." + wn.Name + ".extra_volumes[" + strconv.Itoa(i) + "]: Invalid value: \"label\": is duplicated")
				}
				if ev.MountPath == ev2.MountPath {
					return errors.New("spec.worker_nodes." + wn.Name + ".extra_volumes[" + strconv.Itoa(i) + "]: Invalid value: \"mount_path\": is duplicated")
				}
			}
		}
	}
	return nil
}

func validateVolumeType(t string, supportedTypes []string) error {
	if t != "" && !commons.Contains(supportedTypes, t) {
		return errors.New(t + ", supported types: " + fmt.Sprint(strings.Join(supportedTypes, ", ")))
	}
	return nil
}
