package kubernetes

// Code generated by stub-gen; DO NOT EDIT.

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rosskirkpat/revvy/pkg/client"
)

// ClusterRoleBinding wraps a Kubernetes ClusterRoleBinding.
type ClusterRoleBinding struct {
	rbacv1.ClusterRoleBinding

	client client.Client
}

// NewClusterRoleBinding creates a ClusterRoleBinding from its Kubernetes ClusterRoleBinding.
func NewClusterRoleBinding(client client.Client, clusterrolebinding rbacv1.ClusterRoleBinding) (ClusterRoleBinding, error) {
	createdClusterRoleBinding, err := client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		Create(client.Ctx, &clusterrolebinding, metav1.CreateOptions{})
	if err != nil {
		return ClusterRoleBinding{}, fmt.Errorf("failed to create clusterrolebinding %s: %w", clusterrolebinding.Name, err)
	}

	return ClusterRoleBinding{
		ClusterRoleBinding: *createdClusterRoleBinding,
		client: client,
	}, nil
}

// GetClusterRoleBinding gets a clusterrolebinding.
func GetClusterRoleBinding(client client.Client, name string) (ClusterRoleBinding, error) {
	options := metav1.GetOptions{}

	clusterrolebinding, err := client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		Get(client.Ctx, name, options)
	if err != nil {
		return ClusterRoleBinding{}, fmt.Errorf("failed to get clusterrolebinding %s: %w", name, err)
	}

	return ClusterRoleBinding{
		ClusterRoleBinding: *clusterrolebinding,
		client: client,
	}, nil
}

// ListClusterRoleBindings lists all clusterrolebindings.
func ListClusterRoleBindings(client client.Client) ([]ClusterRoleBinding, error) {
	options := metav1.ListOptions{}

	list, err := client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		List(client.Ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list clusterrolebindings: %w", err)
	}

	clusterrolebindings := make([]ClusterRoleBinding, 0, len(list.Items))

	for _, item := range list.Items {
		clusterrolebindings = append(clusterrolebindings, ClusterRoleBinding{
			ClusterRoleBinding: item,
			client: client,
		})
	}

	return clusterrolebindings, nil
}

// Delete deletes a ClusterRoleBinding from the Kubernetes cluster.
func (clusterrolebinding ClusterRoleBinding) Delete() error {
	options := metav1.DeleteOptions{}

	err := clusterrolebinding.client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		Delete(clusterrolebinding.client.Ctx, clusterrolebinding.Name, options)
	if err != nil {
		return fmt.Errorf("failed to delete clusterrolebinding %s: %w", clusterrolebinding.Name, err)
	}

	return nil
}

// Update gets the current ClusterRoleBinding status.
func (clusterrolebinding *ClusterRoleBinding) Update() error {
	options := metav1.GetOptions{}

	update, err := clusterrolebinding.client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		Get(clusterrolebinding.client.Ctx, clusterrolebinding.Name, options)
	if err != nil {
		return fmt.Errorf("failed to update clusterrolebinding %s: %w", clusterrolebinding.Name, err)
	}

	clusterrolebinding.ClusterRoleBinding = *update

	return nil
}

// Save saves the current ClusterRoleBinding.
func (clusterrolebinding *ClusterRoleBinding) Save() error {
	update, err := clusterrolebinding.client.Kubernetes.
		RbacV1().
		ClusterRoleBindings().
		Update(clusterrolebinding.client.Ctx, &clusterrolebinding.ClusterRoleBinding, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to save clusterrolebinding %s: %w", clusterrolebinding.Name, err)
	}

	clusterrolebinding.ClusterRoleBinding = *update

	return nil
}
