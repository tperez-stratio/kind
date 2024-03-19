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

package create

import (
	"fmt"
	"time"

	"github.com/alessio/shellescape"

	"sigs.k8s.io/kind/pkg/cluster/internal/delete"
	"sigs.k8s.io/kind/pkg/cluster/internal/providers"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
	"sigs.k8s.io/kind/pkg/internal/apis/config"
	"sigs.k8s.io/kind/pkg/internal/apis/config/encoding"
	"sigs.k8s.io/kind/pkg/internal/cli"
	"sigs.k8s.io/kind/pkg/log"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions"
	configaction "sigs.k8s.io/kind/pkg/cluster/internal/create/actions/config"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/createworker"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/installcni"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/installstorage"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/kubeadminit"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/kubeadmjoin"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/loadbalancer"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/waitforready"
	"sigs.k8s.io/kind/pkg/cluster/internal/kubeconfig"
)

const (
	// Typical host name max limit is 64 characters (https://linux.die.net/man/2/sethostname)
	// We append -control-plane (14 characters) to the cluster name on the control plane container
	clusterNameMax = 50
)

// ClusterOptions holds cluster creation options
type ClusterOptions struct {
	Config       *config.Cluster
	NameOverride string // overrides config.Name

	// Stratio
	VaultPassword      string
	DescriptorPath     string
	MoveManagement     bool
	AvoidCreation      bool
	KeosCluster        commons.KeosCluster
	ClusterConfig      *commons.ClusterConfig
	ClusterCredentials commons.ClusterCredentials
	DockerRegUrl       string

	// Force local container delete before creating the cluster if it already exists
	ForceDelete bool
	// NodeImage overrides the nodes' images in Config if non-zero
	NodeImage      string
	Retain         bool
	WaitForReady   time.Duration
	KubeconfigPath string
	// see https://github.com/kubernetes-sigs/kind/issues/324
	StopBeforeSettingUpKubernetes bool // if false kind should setup kubernetes after creating nodes
	// Options to control output
	DisplayUsage      bool
	DisplaySalutation bool
}

// Cluster creates a cluster
func Cluster(logger log.Logger, p providers.Provider, opts *ClusterOptions) error {
	// validate provider first
	if err := validateProvider(p); err != nil {
		return err
	}

	// default / process options (namely config)
	if err := fixupOptions(opts); err != nil {
		return err
	}

	// Check if the cluster name already exists
	if err := alreadyExists(p, opts.Config.Name); err != nil {
		if opts.ForceDelete {
			// Delete current cluster container
			_ = delete.Cluster(nil, p, opts.Config.Name, "")
		} else {
			return errors.Errorf("A cluster with the name %q already exists \n"+
				"Please use a different cluster name or delete the current container with --delete-previous flag", opts.Config.Name)
		}
	}

	// warn if cluster name might typically be too long
	if len(opts.Config.Name) > clusterNameMax {
		logger.Warnf("cluster name %q is probably too long, this might not work properly on some systems", opts.Config.Name)
	}

	// then validate
	if err := opts.Config.Validate(); err != nil {
		return err
	}

	// setup a status object to show progress to the user
	status := cli.StatusForLogger(logger)

	// we're going to start creating now, tell the user
	logger.V(0).Infof("Creating temporary cluster %q ...\n", opts.Config.Name)

	// Create node containers implementing defined config Nodes
	if err := p.Provision(status, opts.Config, opts.DockerRegUrl); err != nil {
		// In case of errors nodes are deleted (except if retain is explicitly set)
		if !opts.Retain {
			_ = delete.Cluster(logger, p, opts.Config.Name, opts.KubeconfigPath)
		}
		return err
	}

	// TODO(bentheelder): make this controllable from the command line?
	actionsToRun := []actions.Action{
		loadbalancer.NewAction(), // setup external loadbalancer
		configaction.NewAction(), // setup kubeadm config
	}
	if !opts.StopBeforeSettingUpKubernetes {
		actionsToRun = append(actionsToRun,
			kubeadminit.NewAction(opts.Config), // run kubeadm init
		)
		// this step might be skipped, but is next after init
		if !opts.Config.Networking.DisableDefaultCNI {
			actionsToRun = append(actionsToRun,
				installcni.NewAction(), // install CNI
			)
		}
		// add remaining steps
		actionsToRun = append(actionsToRun,
			installstorage.NewAction(),                // install StorageClass
			kubeadmjoin.NewAction(),                   // run kubeadm join
			waitforready.NewAction(opts.WaitForReady), // wait for cluster readiness
		)

		// add Stratio step
		actionsToRun = append(actionsToRun,
			createworker.NewAction(opts.VaultPassword, opts.DescriptorPath, opts.MoveManagement, opts.AvoidCreation, opts.KeosCluster, opts.ClusterCredentials, opts.ClusterConfig), // create worker k8s cluster
		)
	}

	// run all actions
	actionsContext := actions.NewActionContext(logger, status, p, opts.Config)
	for _, action := range actionsToRun {
		if err := action.Execute(actionsContext); err != nil {
			if !opts.Retain {
				_ = delete.Cluster(logger, p, opts.Config.Name, opts.KubeconfigPath)
			}
			return err
		}
	}

	// skip the rest if we're not setting up kubernetes
	if opts.StopBeforeSettingUpKubernetes {
		return nil
	}

	// try exporting kubeconfig with backoff for locking failures
	// TODO: factor out into a public errors API w/ backoff handling?
	// for now this is easier than coming up with a good API
	var err error
	for _, b := range []time.Duration{0, time.Millisecond, time.Millisecond * 50, time.Millisecond * 100} {
		time.Sleep(b)
		if err = kubeconfig.Export(p, opts.Config.Name, opts.KubeconfigPath, true); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}

	// add Stratio action: delete the local cluster
	if !opts.Retain {
		actionsContext.Status.Start("Cleaning up temporary cluster 🧹")
		defer actionsContext.Status.End(false)
		_ = delete.Cluster(logger, p, opts.Config.Name, opts.KubeconfigPath)
		actionsContext.Status.End(true) // End Cleaning up local cluster
	}

	// optionally display usage
	// if opts.DisplayUsage {
	// 	logUsage(logger, opts.Config.Name, opts.KubeconfigPath)
	// }
	// optionally give the user a friendly salutation
	if opts.DisplaySalutation {
		logger.V(0).Info("")
		logSalutation(logger)
	}

	return nil
}

// alreadyExists returns an error if the cluster name already exists
// or if we had an error checking
func alreadyExists(p providers.Provider, name string) error {
	n, err := p.ListNodes(name)
	if err != nil {
		return err
	}
	if len(n) != 0 {
		return errors.Errorf("node(s) already exist for a cluster with the name %q", name)
	}
	return nil
}

func logUsage(logger log.Logger, name, explicitKubeconfigPath string) {
	// construct a sample command for interacting with the cluster
	kctx := kubeconfig.ContextForCluster(name)
	sampleCommand := fmt.Sprintf("kubectl cluster-info --context %s", kctx)
	if explicitKubeconfigPath != "" {
		// explicit path, include this
		sampleCommand += " --kubeconfig " + shellescape.Quote(explicitKubeconfigPath)
	}
	logger.V(0).Infof(`Set kubectl context to "%s"`, kctx)
	logger.V(0).Infof("You can now use your cluster with:\n\n" + sampleCommand)
}

func logSalutation(logger log.Logger) {
	salutations := []string{
		// "Kubeconfig file: ",
		"The cluster has been installed successfully. Please refer to the documents below on how to proceed:",
		"1. Post-installation Stratio cloud-provisioner documentation",
		"2. Stratio KEOS documentation",
	}

    for _, salutation := range salutations {
        logger.V(0).Info(salutation)
    }
}

func fixupOptions(opts *ClusterOptions) error {
	// do post processing for options
	// first ensure we at least have a default cluster config
	if opts.Config == nil {
		cfg, err := encoding.Load("")
		if err != nil {
			return err
		}
		opts.Config = cfg
	}

	if opts.NameOverride != "" {
		opts.Config.Name = opts.NameOverride
	}

	// if NodeImage was set, override the image on all nodes
	if opts.NodeImage != "" {
		// Apply image override to all the Nodes defined in Config
		// TODO(fabrizio pandini): this should be reconsidered when implementing
		//     https://github.com/kubernetes-sigs/kind/issues/133
		for i := range opts.Config.Nodes {
			opts.Config.Nodes[i].Image = opts.NodeImage
		}
	}

	// default config fields (important for usage as a library, where the config
	// may be constructed in memory rather than from disk)
	config.SetDefaultsCluster(opts.Config)

	return nil
}

func validateProvider(p providers.Provider) error {
	info, err := p.Info()
	if err != nil {
		return err
	}
	if info.Rootless {
		if !info.Cgroup2 {
			return errors.New("running kind with rootless provider requires cgroup v2, see https://kind.sigs.k8s.io/docs/user/rootless/")
		}
		if !info.SupportsMemoryLimit || !info.SupportsPidsLimit || !info.SupportsCPUShares {
			return errors.New("running kind with rootless provider requires setting systemd property \"Delegate=yes\", see https://kind.sigs.k8s.io/docs/user/rootless/")
		}
	}
	return nil
}
