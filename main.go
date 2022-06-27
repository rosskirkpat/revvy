package revvy

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	runtime2 "runtime"
	"syscall"

	"github.com/rosskirkpat/revvy/pkg/client"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	namespace             = "namespace"
	node                  = "node"
	clusterRole           = "clusterrole"
	clusterRoleBinding    = "clusterRoleBinding"
	persistentVolumeClaim = "persistentvolumeclaim"
	pod                   = "pod"
	role                  = "role"
	roleBinding           = "rolebinding"
	secret                = "secret"
	service               = "service"
	serviceAccount        = "serviceaccount"
	statefulSet           = "statefulset"
	sleBusyBoxImage       = "registry.suse.com/bci/bci-busybox:15.4"
	defaultName           = "kscale"
	defaultNamespace      = "kscale"
	defaultPodCommand     = "sleep 30;exit"
	maxSecretSize         = 1023
)

var (
	t                 = new(bool)
	f                 = new(bool)
	i                 = new(int32)
	DefaultConfigFile = fmt.Sprintf(os.Getenv("HOME") + defaultName + "config.yaml")
)

type Config struct {
	Scale     Scaler `json:"scale" yaml:"scale"`
	Namespace string `json:"namespace" yaml:"namespace"`
	client    client.Client
	Type      ResourceType
	Obj       runtime.Object
	LogLevel  string `yaml:"loglevel, logLevel"`
}

type Scaler struct {
	Resource  string `json:"resource" yaml:"resource"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Request   int    `json:"request" yaml:"request"`
}

type ResourceType struct {
	namespace             corev1.Namespace
	secret                corev1.Secret
	serviceAccount        corev1.ServiceAccount
	pod                   corev1.Pod
	node                  corev1.Node
	persistentVolumeClaim corev1.PersistentVolumeClaim
	statefulSet           appsv1.StatefulSet
	role                  rbacv1.Role
	roleBinding           rbacv1.RoleBinding
	clusterRoleBinding    rbacv1.ClusterRoleBinding
	clusterRole           rbacv1.ClusterRole
	service               corev1.Service
}

//{
//"scale": { "namespace", "default", 500}
//"scale": { "pod", "default", 500}
//"scale": { "secret", "default", 500}
//"scale": { "serviceaccount", "default", 500}
//"scale": { "service", "default", 500}
//"scale": { "rolebinding", "default", 500}
//}

// LoadConfig returns a new decoded Config struct
func LoadConfig(path string) (*Config, error) {
	// Create config structure
	config := &Config{}

	// Open config file
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logrus.Errorf("failed to open config file: %v", err)
		}
	}(file)

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

//
//func (config *Config) ParseConfig() (*viper.Viper, error) {
//	// Get home directory for current user
//	homeDir := os.Getenv("HOME")
//	if homeDir == "" {
//		logrus.Warn("cannot get current user home directory: environment variable not set")
//	} else {
//		viper.AddConfigPath(homeDir + defaultName + "config.yaml")
//	}
//	conf := viper.New()
//	viper.SetConfigName("config")
//	viper.SetConfigType("yaml")
//	viper.AddConfigPath(".")
//
//	err := viper.ReadInConfig()
//	if err != nil {
//		panic(fmt.Errorf("fatal error while reading config file: %w", err))
//	}
//	conf.Get(config.Scale.Resource)
//	err = viper.Unmarshal(&config)
//	if err != nil {
//		panic(fmt.Errorf("unable to decode into struct, %v", err))
//	}
//	return conf, nil
//}

func (config Config) Parser(c client.Client) error {
	*t = true
	*f = false
	*i = int32(config.Scale.Request)

	switch config.Scale.Resource {
	case clusterRole:
		err := config.Scale.Scale(c, config, &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
				Namespace:    defaultNamespace},
		})
		if err != nil {
			return err
		}
	case clusterRoleBinding:
		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
				Namespace:    defaultNamespace,
			},
		}
		err := config.Scale.Scale(c, config, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
				Namespace:    defaultNamespace,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: cr.GroupVersionKind().Group,
				Kind:     cr.GroupVersionKind().Kind,
				Name:     cr.Name,
			},
		})
		if err != nil {
			return err
		}
	case namespace:
		err := config.Scale.Scale(c, config, &corev1.Namespace{})
		if err != nil {
			return err
		}
	case node:
		err := config.Scale.Scale(c, config, &corev1.Node{})
		if err != nil {
			return err
		}
	case persistentVolumeClaim:
		err := config.Scale.Scale(c, config, &corev1.PersistentVolumeClaim{})
		if err != nil {
			return err
		}
	case pod:
		err := config.Scale.Scale(c, config, &corev1.Pod{})
		if err != nil {
			return err
		}
	case role:
		err := config.Scale.Scale(c, config, &rbacv1.Role{})
		if err != nil {
			return err
		}
	case roleBinding:
		err := config.Scale.Scale(c, config, &rbacv1.RoleBinding{})
		if err != nil {
			return err
		}
	case secret:
		d := make(map[string][]byte)
		for i := 0; i < config.Scale.Request; i++ {
			// add one to ensure we do not generate a 0-byte sized secret
			n := rand.Intn(maxSecretSize) + 1
			d["data"] = make([]byte, n)
		}

		err := config.Scale.Scale(c, config, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
				Namespace:    defaultNamespace,
			},
			Immutable: t,
			Data:      d,
			Type:      corev1.SecretTypeOpaque,
		})
		if err != nil {
			return err
		}

	case service:
		err := config.Scale.Scale(c, config, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
			},
			Spec: corev1.ServiceSpec{
				ExternalName: defaultName,
			},
		})
		if err != nil {
			return err
		}
	case serviceAccount:
		err := config.Scale.Scale(c, config, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
			},
			AutomountServiceAccountToken: t,
		})
		if err != nil {
			return err
		}
	case statefulSet:
		p := new(bool)
		*p = false
		err := config.Scale.Scale(c, config, &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: defaultName,
			},
			Spec: appsv1.StatefulSetSpec{
				Replicas: i,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: defaultName,
						Namespace:    defaultNamespace,
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{{
							Name:            defaultName,
							Image:           sleBusyBoxImage,
							Command:         []string{defaultPodCommand},
							ImagePullPolicy: "IfNotPresent",
							SecurityContext: &corev1.SecurityContext{
								Privileged:               f,
								RunAsNonRoot:             t,
								ReadOnlyRootFilesystem:   t,
								AllowPrivilegeEscalation: f,
							},
						},
						},
					},
				},
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("[Parser]: %s resource type was unexpected", config.Scale.Resource)
	}
	return nil
}

func (s *Scaler) Scale(c client.Client, config Config, obj runtime.Object) error {
	// TODO: validation
	// TODO: concurrent creations for multiple resource types
	// Validate the path first

	r := config.Scale.Request
	jobs := make(chan int, r)
	results := make(chan int, r)
	for w := 1; w <= (runtime2.NumCPU() / 2); w++ {
		go s.kscaler(c, obj, jobs, results)
	}

	//for i := 0; i < r; i++ {
	//	err := c.Create(c.Ctx, s.Namespace, obj, obj, metav1.CreateOptions{})
	//	if err != nil {
	//		logrus.Errorf("failed during create: %v", err)
	//		break
	//	}
	//}
	for j := 1; j <= r; j++ {
		jobs <- j
	}
	close(jobs)

	for a := 1; a <= r; a++ {
		<-results
	}
	logrus.Infof("finished creating (%v) resources of kind (%v)",
		r,
		obj.GetObjectKind().GroupVersionKind().Kind)
	return nil
}

func (s *Scaler) kscaler(c client.Client, obj runtime.Object, jobs <-chan int, results chan<- int) {
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		60,
	)
	defer cancel()
	signal.Notify(runChan, os.Interrupt, syscall.SIGABRT)
	for j := range jobs {
		err := c.Create(ctx, s.Namespace, obj, obj, metav1.CreateOptions{
			FieldManager: defaultName,
		})
		if err != nil {
			logrus.Errorf("failed during create: %v", err)
			break
		}
		results <- j * 2
	}
	// Block on this channel listening for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interrupt := <-runChan

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	logrus.Infof("kscale is shutting down due to %+v\n", interrupt)
}

func (config *Config) setVerbosityLevel() {
	switch config.LogLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
	logrus.SetOutput(os.Stderr)
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")

	// Actually parse the flags
	flag.Parse()

	// Validate the path first
	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	// Return the configuration path
	return configPath, nil
}

func main() {
	// Generate our config based on the config supplied
	cfgPath, err := ParseFlags()
	if err != nil {
		logrus.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		logrus.Warn("failed to load config from specified path, attempting default config path")
		cfg, err = LoadConfig(DefaultConfigFile)
		if err != nil {
			panic(fmt.Errorf("failed to load config from any path, exiting: %v", err))

		}
	}

	// Run kscale
	err = cfg.Parser(cfg.client)
	if err != nil {
		logrus.Fatal(err)
		return
	}
}
