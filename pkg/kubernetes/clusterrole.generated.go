package kubernetes

// Code generated by stub-gen; DO NOT EDIT.

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rosskirkpat/revvy/pkg/client"
)

// ClusterRole wraps a Kubernetes ClusterRole.
type ClusterRole struct {
	rbacv1.ClusterRole

	client client.Client
}

// NewClusterRole creates a ClusterRole from its Kubernetes ClusterRole.
func NewClusterRole(client client.Client, clusterrole rbacv1.ClusterRole) (ClusterRole, error) {
	createdClusterRole, err := client.Kubernetes.
		RbacV1().
		ClusterRoles().
		Create(client.Ctx, &clusterrole, metav1.CreateOptions{})
	if err != nil {
		return ClusterRole{}, fmt.Errorf("failed to create clusterrole %s: %w", clusterrole.Name, err)
	}

	return ClusterRole{
		ClusterRole: *createdClusterRole,
		client:      client,
	}, nil
}

// GetClusterRole gets a clusterrole.
func GetClusterRole(client client.Client, name string) (ClusterRole, error) {
	options := metav1.GetOptions{}

	clusterrole, err := client.Kubernetes.
		RbacV1().
		ClusterRoles().
		Get(client.Ctx, name, options)
	if err != nil {
		return ClusterRole{}, fmt.Errorf("failed to get clusterrole %s: %w", name, err)
	}

	return ClusterRole{
		ClusterRole: *clusterrole,
		client:      client,
	}, nil
}

// ListClusterRoles lists all clusterroles.
func ListClusterRoles(client client.Client) ([]ClusterRole, error) {
	options := metav1.ListOptions{}

	list, err := client.Kubernetes.
		RbacV1().
		ClusterRoles().
		List(client.Ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list clusterroles: %w", err)
	}

	clusterroles := make([]ClusterRole, 0, len(list.Items))

	for _, item := range list.Items {
		clusterroles = append(clusterroles, ClusterRole{
			ClusterRole: item,
			client:      client,
		})
	}

	return clusterroles, nil
}

// Delete deletes a ClusterRole from the Kubernetes cluster.
func (clusterrole ClusterRole) Delete() error {
	options := metav1.DeleteOptions{}

	err := clusterrole.client.Kubernetes.
		RbacV1().
		ClusterRoles().
		Delete(clusterrole.client.Ctx, clusterrole.Name, options)
	if err != nil {
		return fmt.Errorf("failed to delete clusterrole %s: %w", clusterrole.Name, err)
	}

	return nil
}

// Update gets the current ClusterRole status.
func (clusterrole *ClusterRole) Update() error {
	options := metav1.GetOptions{}

	update, err := clusterrole.client.Kubernetes.
		RbacV1().
		ClusterRoles().
		Get(clusterrole.client.Ctx, clusterrole.Name, options)
	if err != nil {
		return fmt.Errorf("failed to update clusterrole %s: %w", clusterrole.Name, err)
	}

	clusterrole.ClusterRole = *update

	return nil
}

// Save saves the current ClusterRole.
func (clusterrole *ClusterRole) Save() error {
	update, err := clusterrole.client.Kubernetes.
		RbacV1().
		ClusterRoles().
		Update(clusterrole.client.Ctx, &clusterrole.ClusterRole, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to save clusterrole %s: %w", clusterrole.Name, err)
	}

	clusterrole.ClusterRole = *update

	return nil
}
