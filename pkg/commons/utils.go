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

package commons

import (
	"bytes"
	"context"
	"time"
	"unicode"

	"os"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	vault "github.com/sosedoff/ansible-vault-go"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/errors"
)

const secretName = "secrets.yml"
const secretPath = "./" + secretName

func decryptFile(filePath string, vaultPassword string) (string, error) {
	data, err := vault.DecryptFile(filePath, vaultPassword)
	if err != nil {
		return "", err
	}
	var secret SecretsFile
	_ = yaml.Unmarshal([]byte(data), &secret)
	return data, nil
}

func convertStringMapToInterfaceMap(inputMap map[string]string) map[string]interface{} {
	outputMap := make(map[string]interface{})
	for key, value := range inputMap {
		outputMap[key] = value
	}
	return outputMap
}

func EnsureSecretsFile(spec KeosSpec, vaultPassword string, clusterCredentials ClusterCredentials) error {
	var err error

	edited := false

	credentials := clusterCredentials.ProviderCredentials
	dockerRegistry := clusterCredentials.KeosRegistryCredentials
	dockerRegistries := clusterCredentials.DockerRegistriesCredentials
	helmRepository := clusterCredentials.HelmRepositoryCredentials
	github_token := clusterCredentials.GithubToken

	_, err = os.Stat(secretPath)
	if err != nil {
		secretMap := map[string]interface{}{}
		if github_token != "" {
			secretMap["github_token"] = github_token
		}
		if len(credentials) > 0 {
			creds := convertStringMapToInterfaceMap(credentials)
			creds = ConvertMapKeysToSnakeCase(creds)
			secretMap[spec.InfraProvider] = map[string]interface{}{"credentials": creds}
		}

		if len(dockerRegistry) > 0 {
			externalReg := convertStringMapToInterfaceMap(dockerRegistry)
			externalReg = ConvertMapKeysToSnakeCase(externalReg)
			secretMap["docker_registry"] = externalReg
		}

		if len(dockerRegistries) > 0 {
			for i, dockerReg := range dockerRegistries {
				dockerRegistries[i] = ConvertMapKeysToSnakeCase(dockerReg)
			}
			secretMap["docker_registries"] = dockerRegistries
		}

		if len(helmRepository) > 0 {
			helmRepo := convertStringMapToInterfaceMap(helmRepository)
			helmRepo = ConvertMapKeysToSnakeCase(helmRepo)
			secretMap["helm_repository"] = helmRepo
		}

		secretFileMap := map[string]map[string]interface{}{
			"secrets": secretMap,
		}

		err = encryptSecret(secretFileMap, vaultPassword)
		if err != nil {
			return err
		}
		return nil
	}
	// En caso de que exista
	secretRaw, err := decryptFile(secretPath, vaultPassword)
	if err != nil {
		return err
	}
	secretMap := map[string]map[string]interface{}{}
	err = yaml.Unmarshal([]byte(secretRaw), &secretMap)
	if err != nil {
		return err
	}

	if secretMap["secrets"][spec.InfraProvider] == nil && len(credentials) > 0 {
		edited = true
		creds := convertStringMapToInterfaceMap(credentials)
		creds = ConvertMapKeysToSnakeCase(creds)
		secretMap["secrets"][spec.InfraProvider] = map[string]interface{}{"credentials": creds}
	}

	if secretMap["secrets"]["docker_registry"] == nil && len(dockerRegistry) > 0 {
		edited = true
		externalReg := convertStringMapToInterfaceMap(dockerRegistry)
		externalReg = ConvertMapKeysToSnakeCase(externalReg)
		secretMap["secrets"]["docker_registry"] = externalReg
	}
	if secretMap["secrets"]["helm_repository"] == nil && len(helmRepository) > 0 {
		edited = true
		helmRepo := convertStringMapToInterfaceMap(helmRepository)
		helmRepo = ConvertMapKeysToSnakeCase(helmRepo)
		secretMap["secrets"]["docker_registry"] = helmRepo
	}
	if secretMap["secrets"]["github_token"] == nil && github_token != "" {
		edited = true
		secretMap["secrets"]["github_token"] = github_token
	}
	if secretMap["secrets"]["docker_registries"] == nil && len(dockerRegistries) > 0 {
		edited = true
		for i, dockerReg := range dockerRegistries {
			dockerRegistries[i] = ConvertMapKeysToSnakeCase(dockerReg)
		}
		secretMap["secrets"]["docker_registries"] = dockerRegistries
	}
	if edited {
		err = encryptSecret(secretMap, vaultPassword)
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}

// func RewriteDescriptorFile(descriptorPath string, keosCluster KeosCluster, resources ...interface{}) error {
func RewriteDescriptorFile(descriptorPath string) error {

	descriptorRAW, err := os.ReadFile(descriptorPath)
	manifests := strings.Split(string(descriptorRAW), "---\n")
	keosClusterIndex := -1
	for i, m := range manifests {
		if strings.Contains(m, "kind: KeosCluster") {
			keosClusterIndex = i
		}
	}
	if keosClusterIndex == -1 {
		return errors.New("KeosCluster manifest not found.")
	}

	var data yaml.Node
	err = yaml.Unmarshal([]byte(manifests[keosClusterIndex]), &data)
	if err != nil {
		return err
	}

	yamlNodes := removeKey(data.Content, "credentials")

	b, err := yaml.Marshal(yamlNodes[0])
	if err != nil {
		return err
	}
	descriptor := append(manifests[:keosClusterIndex], string(b))
	descriptor = append(descriptor, manifests[keosClusterIndex+1:]...)
	descriptorRewrited := strings.Join(descriptor, "---\n")

	err = os.WriteFile(descriptorPath, []byte(descriptorRewrited), 0644)
	if err != nil {
		return err
	}

	return nil
}

func encryptSecret(secretMap map[string]map[string]interface{}, vaultPassword string) error {

	var b bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&b)
	yamlEncoder.SetIndent(2)
	yamlEncoder.Encode(&secretMap)

	err := vault.EncryptFile(secretPath, b.String(), vaultPassword)
	if err != nil {
		return err
	}

	return nil
}

func removeKey(nodes []*yaml.Node, key string) []*yaml.Node {
	newNodes := []*yaml.Node{}
	for _, node := range nodes {
		if node.Kind == yaml.MappingNode {
			j := 0
			for j < len(node.Content)/2 {
				if node.Content[j*2].Value == key {
					node.Content = append(node.Content[:j*2], node.Content[j*2+2:]...)
					continue
				}
				j++
			}
			node.Content = removeKey(node.Content, key)
		}
		if node.Kind == yaml.SequenceNode {
			node.Content = removeKey(node.Content, key)
		}
		newNodes = append(newNodes, node)
	}
	return newNodes
}

func ExecuteCommand(n nodes.Node, command string, timeout int, envVars ...[]string) (string, error) {
	var err error
	var raw bytes.Buffer
	cmd := n.Command("sh", "-c", command)
	if len(envVars) > 0 {
		cmd.SetEnv(envVars[0]...)
	}
	retryConditions := []string{"dial tcp: lookup", "NotFound", "timed out waiting"}
	provisionCommands := strings.Contains(command, "kubectl") || strings.Contains(command, "helm") || strings.Contains(command, "clusterctl")
	for i := 0; i < 3; i++ {
		raw = bytes.Buffer{}
		err = cmd.SetStdout(&raw).SetStderr(&raw).Run()
		retry := false
		for _, condition := range retryConditions {
			if strings.Contains(raw.String(), condition) {
				retry = true
			}
		}
		if err == nil || !(provisionCommands && retry) {
			break
		}
		time.Sleep(time.Duration(timeout) * time.Second)
	}
	if strings.Contains(raw.String(), "Error:") || strings.Contains(raw.String(), "Error from server") {
		return "", errors.New("Command Output: " + raw.String())
	}
	if err != nil {
		return "", err
	}
	return raw.String(), nil
}

func snakeCase(s string) string {
	var result []rune
	for i, c := range s {
		if unicode.IsUpper(c) {
			if i > 0 && !unicode.IsUpper(rune(s[i-1])) {
				result = append(result, '_')
			}
			result = append(result, unicode.ToLower(c))
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}

func ConvertMapKeysToSnakeCase(m map[string]interface{}) map[string]interface{} {
	newMap := make(map[string]interface{})
	for k, v := range m {
		newKey := snakeCase(k)
		newMap[newKey] = v
	}
	return newMap
}

// contains checks if a string is present in a slice
func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func AWSGetConfig(ctx context.Context, secrets map[string]string, region string) (aws.Config, error) {
	customProvider := credentials.NewStaticCredentialsProvider(
		secrets["AccessKey"], secrets["SecretKey"], "",
	)
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithCredentialsProvider(customProvider),
		config.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, err
	}
	return cfg, nil
}

func AWSIsPrivateSubnet(ctx context.Context, svc *ec2.Client, subnetID *string) (bool, error) {
	keyname := "association.subnet-id"
	drtInput := &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   &keyname,
				Values: []string{*subnetID},
			},
		},
	}
	rt, err := svc.DescribeRouteTables(ctx, drtInput)
	if err != nil {
		return false, err
	}

	for _, associatedRouteTable := range rt.RouteTables {
		for i := range associatedRouteTable.Routes {
			route := associatedRouteTable.Routes[i]
			// Check if route is public
			if route.DestinationCidrBlock != nil &&
				route.GatewayId != nil &&
				*route.DestinationCidrBlock == "0.0.0.0/0" &&
				strings.Contains(*route.GatewayId, "igw") {
				return false, nil // Public subnet
			}
		}
	}

	return true, nil
}

func AWSGetPrivateAZs(ctx context.Context, svc *ec2.Client, subnets []Subnets) ([]string, error) {
	var azs []string
	for _, s := range subnets {
		isPrivate, err := AWSIsPrivateSubnet(ctx, svc, &s.SubnetId)
		if err != nil {
			return nil, nil
		}
		if isPrivate {
			sid := &ec2.DescribeSubnetsInput{
				SubnetIds: []string{s.SubnetId},
			}
			ds, err := svc.DescribeSubnets(ctx, sid)
			if err != nil {
				return nil, nil
			}
			for _, describeSubnet := range ds.Subnets {
				if !slices.Contains(azs, *describeSubnet.AvailabilityZone) {
					azs = append(azs, *describeSubnet.AvailabilityZone)
				}
			}
		}
	}
	return azs, nil
}

func AWSGetAZs(ctx context.Context, svc *ec2.Client) ([]string, error) {
	var azs []string
	result, err := svc.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return nil, err
	}
	for i, az := range result.AvailabilityZones {
		if i == 3 {
			break
		}
		azs = append(azs, *az.ZoneName)
	}
	return azs, nil
}

func AzureGetConfig(secrets map[string]string) (*azidentity.ClientSecretCredential, error) {
	cfg, err := azidentity.NewClientSecretCredential(
		secrets["TenantID"], secrets["ClientID"], secrets["ClientSecret"], nil,
	)
	if err != nil {
		return &azidentity.ClientSecretCredential{}, err
	}
	return cfg, nil
}
