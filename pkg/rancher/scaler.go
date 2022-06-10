package rancher

import (
	"github.com/rosskirkpat/descale/pkg/client"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type Scaler struct {
	config client.ScaleConfig
	client client.Client
}

func (s *Scaler) Scale(c client.Client, requested int, obj runtime.Object) error {
	// TODO: validation
	// TODO: concurrent creations for multiple resource types
	go func(obj runtime.Object) {
		for i := 0; i < requested; i++ {
			err := c.Create(c.Ctx, s.config.Namespace, s.config.Obj, s.config.Obj, metav1.CreateOptions{})
			if err != nil {
				logrus.Errorf("failed during create: %v", err)
				return
			}
		}
		logrus.Infof("finished creating (%v) resources of kind (%v)",
			requested,
			obj.GetObjectKind().GroupVersionKind().Kind)
	}(obj)
	// TODO: channels
	return nil
}
