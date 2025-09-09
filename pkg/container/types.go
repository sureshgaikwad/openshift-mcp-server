package container

import (
	"context"
	"io"
	"time"
)

// ContainerRuntime defines the interface for container runtime operations
type ContainerRuntime interface {
	// Image operations
	BuildImage(ctx context.Context, opts BuildOptions) (*BuildResult, error)
	PushImage(ctx context.Context, opts PushOptions) (*PushResult, error)
	PullImage(ctx context.Context, opts PullOptions) (*PullResult, error)
	ListImages(ctx context.Context, opts ListImagesOptions) ([]*Image, error)
	InspectImage(ctx context.Context, imageID string) (*ImageInspect, error)
	RemoveImage(ctx context.Context, imageID string, force bool) error
	TagImage(ctx context.Context, sourceImage, targetImage string) error

	// Container operations
	RunContainer(ctx context.Context, opts RunOptions) (*RunResult, error)
	ListContainers(ctx context.Context, opts ListContainersOptions) ([]*Container, error)
	InspectContainer(ctx context.Context, containerID string) (*ContainerInspect, error)
	StopContainer(ctx context.Context, containerID string, timeout *time.Duration) error
	RemoveContainer(ctx context.Context, containerID string, force bool) error
	ContainerLogs(ctx context.Context, containerID string, opts LogsOptions) (io.ReadCloser, error)
	ExecContainer(ctx context.Context, containerID string, opts ExecOptions) (*ExecResult, error)

	// Runtime information
	Version(ctx context.Context) (*RuntimeVersion, error)
	Info(ctx context.Context) (*RuntimeInfo, error)
	IsAvailable() bool
	Name() string
}

// BuildOptions contains options for building container images
type BuildOptions struct {
	ContextDir string            `json:"contextDir"`
	Dockerfile string            `json:"dockerfile"`
	ImageTag   string            `json:"imageTag"`
	BuildArgs  map[string]string `json:"buildArgs,omitempty"`
	Target     string            `json:"target,omitempty"`
	NoCache    bool              `json:"noCache,omitempty"`
	Pull       bool              `json:"pull,omitempty"`
	Quiet      bool              `json:"quiet,omitempty"`
	Platform   string            `json:"platform,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// BuildResult contains the result of a build operation
type BuildResult struct {
	ImageID  string        `json:"imageId"`
	ImageTag string        `json:"imageTag"`
	Duration time.Duration `json:"duration"`
	Output   string        `json:"output"`
	Success  bool          `json:"success"`
	Error    error         `json:"error,omitempty"`
}

// PushOptions contains options for pushing container images
type PushOptions struct {
	ImageTag      string `json:"imageTag"`
	Registry      string `json:"registry,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify,omitempty"`
	Quiet         bool   `json:"quiet,omitempty"`
}

// PushResult contains the result of a push operation
type PushResult struct {
	ImageTag string        `json:"imageTag"`
	Registry string        `json:"registry"`
	Duration time.Duration `json:"duration"`
	Output   string        `json:"output"`
	Success  bool          `json:"success"`
	Error    error         `json:"error,omitempty"`
}

// PullOptions contains options for pulling container images
type PullOptions struct {
	ImageTag      string `json:"imageTag"`
	Registry      string `json:"registry,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify,omitempty"`
	Quiet         bool   `json:"quiet,omitempty"`
}

// PullResult contains the result of a pull operation
type PullResult struct {
	ImageTag string        `json:"imageTag"`
	ImageID  string        `json:"imageId"`
	Duration time.Duration `json:"duration"`
	Output   string        `json:"output"`
	Success  bool          `json:"success"`
	Error    error         `json:"error,omitempty"`
}

// ListImagesOptions contains options for listing images
type ListImagesOptions struct {
	All    bool   `json:"all,omitempty"`
	Filter string `json:"filter,omitempty"`
	Format string `json:"format,omitempty"`
	Quiet  bool   `json:"quiet,omitempty"`
}

// Image represents a container image
type Image struct {
	ID         string            `json:"id"`
	Repository string            `json:"repository"`
	Tag        string            `json:"tag"`
	Digest     string            `json:"digest,omitempty"`
	Created    time.Time         `json:"created"`
	Size       int64             `json:"size"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ImageInspect contains detailed information about a container image
type ImageInspect struct {
	ID           string            `json:"id"`
	RepoTags     []string          `json:"repoTags"`
	RepoDigests  []string          `json:"repoDigests"`
	Created      time.Time         `json:"created"`
	Size         int64             `json:"size"`
	VirtualSize  int64             `json:"virtualSize"`
	Labels       map[string]string `json:"labels,omitempty"`
	Architecture string            `json:"architecture"`
	Os           string            `json:"os"`
	Config       *ImageConfig      `json:"config,omitempty"`
	RootFS       *RootFS           `json:"rootfs,omitempty"`
}

// ImageConfig contains the configuration of a container image
type ImageConfig struct {
	User         string              `json:"user,omitempty"`
	ExposedPorts map[string]struct{} `json:"exposedPorts,omitempty"`
	Env          []string            `json:"env,omitempty"`
	Cmd          []string            `json:"cmd,omitempty"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	WorkingDir   string              `json:"workingDir,omitempty"`
	Labels       map[string]string   `json:"labels,omitempty"`
}

// RootFS contains information about the image's root filesystem
type RootFS struct {
	Type   string   `json:"type"`
	Layers []string `json:"layers"`
}

// RunOptions contains options for running containers
type RunOptions struct {
	Image         string            `json:"image"`
	Name          string            `json:"name,omitempty"`
	Command       []string          `json:"command,omitempty"`
	Entrypoint    []string          `json:"entrypoint,omitempty"`
	Env           []string          `json:"env,omitempty"`
	WorkingDir    string            `json:"workingDir,omitempty"`
	User          string            `json:"user,omitempty"`
	Ports         []PortMapping     `json:"ports,omitempty"`
	Volumes       []VolumeMapping   `json:"volumes,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Detach        bool              `json:"detach,omitempty"`
	Remove        bool              `json:"remove,omitempty"`
	Interactive   bool              `json:"interactive,omitempty"`
	TTY           bool              `json:"tty,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	ReadOnly      bool              `json:"readOnly,omitempty"`
	RestartPolicy string            `json:"restartPolicy,omitempty"`
}

// PortMapping represents a port mapping between host and container
type PortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	HostIP        string `json:"hostIp,omitempty"`
}

// VolumeMapping represents a volume mapping between host and container
type VolumeMapping struct {
	HostPath      string `json:"hostPath"`
	ContainerPath string `json:"containerPath"`
	Mode          string `json:"mode,omitempty"`
}

// RunResult contains the result of running a container
type RunResult struct {
	ContainerID string        `json:"containerId"`
	Name        string        `json:"name"`
	Duration    time.Duration `json:"duration"`
	Output      string        `json:"output"`
	ExitCode    int           `json:"exitCode"`
	Success     bool          `json:"success"`
	Error       error         `json:"error,omitempty"`
}

// ListContainersOptions contains options for listing containers
type ListContainersOptions struct {
	All    bool   `json:"all,omitempty"`
	Filter string `json:"filter,omitempty"`
	Format string `json:"format,omitempty"`
	Quiet  bool   `json:"quiet,omitempty"`
	Size   bool   `json:"size,omitempty"`
}

// Container represents a container
type Container struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	ImageID string            `json:"imageId"`
	Command string            `json:"command"`
	Created time.Time         `json:"created"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Ports   []PortMapping     `json:"ports,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Size    int64             `json:"size,omitempty"`
	Mounts  []MountPoint      `json:"mounts,omitempty"`
}

// MountPoint represents a mount point in a container
type MountPoint struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

// ContainerInspect contains detailed information about a container
type ContainerInspect struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	ImageID         string                    `json:"imageId"`
	Command         []string                  `json:"command"`
	Created         time.Time                 `json:"created"`
	State           *ContainerState           `json:"state,omitempty"`
	Config          *ContainerConfig          `json:"config,omitempty"`
	HostConfig      *ContainerHostConfig      `json:"hostConfig,omitempty"`
	NetworkSettings *ContainerNetworkSettings `json:"networkSettings,omitempty"`
	Mounts          []MountPoint              `json:"mounts,omitempty"`
	Labels          map[string]string         `json:"labels,omitempty"`
}

// ContainerState represents the state of a container
type ContainerState struct {
	Status     string    `json:"status"`
	Running    bool      `json:"running"`
	Paused     bool      `json:"paused"`
	Restarting bool      `json:"restarting"`
	OOMKilled  bool      `json:"oomKilled"`
	Dead       bool      `json:"dead"`
	Pid        int       `json:"pid"`
	ExitCode   int       `json:"exitCode"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
}

// ContainerConfig represents the configuration of a container
type ContainerConfig struct {
	User         string              `json:"user,omitempty"`
	ExposedPorts map[string]struct{} `json:"exposedPorts,omitempty"`
	Env          []string            `json:"env,omitempty"`
	Cmd          []string            `json:"cmd,omitempty"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	WorkingDir   string              `json:"workingDir,omitempty"`
	Labels       map[string]string   `json:"labels,omitempty"`
}

// ContainerHostConfig represents the host configuration of a container
type ContainerHostConfig struct {
	Binds          []string                 `json:"binds,omitempty"`
	PortBindings   map[string][]PortBinding `json:"portBindings,omitempty"`
	RestartPolicy  RestartPolicy            `json:"restartPolicy,omitempty"`
	Privileged     bool                     `json:"privileged,omitempty"`
	ReadonlyRootfs bool                     `json:"readonlyRootfs,omitempty"`
}

// PortBinding represents a port binding
type PortBinding struct {
	HostIP   string `json:"hostIp"`
	HostPort string `json:"hostPort"`
}

// RestartPolicy represents a restart policy
type RestartPolicy struct {
	Name              string `json:"name"`
	MaximumRetryCount int    `json:"maximumRetryCount"`
}

// ContainerNetworkSettings represents the network settings of a container
type ContainerNetworkSettings struct {
	IPAddress string                              `json:"ipAddress"`
	Gateway   string                              `json:"gateway"`
	Bridge    string                              `json:"bridge"`
	Ports     map[string][]PortBinding            `json:"ports,omitempty"`
	Networks  map[string]*NetworkEndpointSettings `json:"networks,omitempty"`
}

// NetworkEndpointSettings represents network endpoint settings
type NetworkEndpointSettings struct {
	IPAddress string `json:"ipAddress"`
	Gateway   string `json:"gateway"`
	NetworkID string `json:"networkId"`
}

// LogsOptions contains options for getting container logs
type LogsOptions struct {
	Follow     bool   `json:"follow,omitempty"`
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Timestamps bool   `json:"timestamps,omitempty"`
	Tail       string `json:"tail,omitempty"`
}

// ExecOptions contains options for executing commands in containers
type ExecOptions struct {
	Command     []string `json:"command"`
	User        string   `json:"user,omitempty"`
	WorkingDir  string   `json:"workingDir,omitempty"`
	Env         []string `json:"env,omitempty"`
	Privileged  bool     `json:"privileged,omitempty"`
	Interactive bool     `json:"interactive,omitempty"`
	TTY         bool     `json:"tty,omitempty"`
}

// ExecResult contains the result of executing a command in a container
type ExecResult struct {
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

// RuntimeVersion contains version information about the container runtime
type RuntimeVersion struct {
	Version    string `json:"version"`
	APIVersion string `json:"apiVersion"`
	GitCommit  string `json:"gitCommit,omitempty"`
	GoVersion  string `json:"goVersion,omitempty"`
	Os         string `json:"os"`
	Arch       string `json:"arch"`
}

// RuntimeInfo contains information about the container runtime
type RuntimeInfo struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Storage         *StorageInfo      `json:"storage,omitempty"`
	Host            *HostInfo         `json:"host,omitempty"`
	Registries      map[string]string `json:"registries,omitempty"`
	ContainersCount int               `json:"containersCount"`
	ImagesCount     int               `json:"imagesCount"`
}

// StorageInfo contains information about storage
type StorageInfo struct {
	Driver      string     `json:"driver"`
	Root        string     `json:"root"`
	RunRoot     string     `json:"runRoot"`
	GraphStatus [][]string `json:"graphStatus,omitempty"`
}

// HostInfo contains information about the host
type HostInfo struct {
	Hostname     string `json:"hostname"`
	Kernel       string `json:"kernel"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	CPUs         int    `json:"cpus"`
	Memory       int64  `json:"memory"`
}
