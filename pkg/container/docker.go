package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// DockerRuntime implements ContainerRuntime interface for Docker
type DockerRuntime struct {
	binaryPath string
}

// findDockerBinary searches for docker binary in multiple locations
// This handles different deployment scenarios including OpenShift environments
func findDockerBinary() string {
	// Common locations where docker might be installed
	commonPaths := []string{
		"/usr/bin/docker",                       // Standard Linux location
		"/usr/local/bin/docker",                 // Alternative Linux location
		"/bin/docker",                           // Some minimal containers
		"/usr/sbin/docker",                      // Some system installations
		"/opt/homebrew/bin/docker",              // macOS Homebrew
		"/home/linuxbrew/.linuxbrew/bin/docker", // Linux Homebrew
		"/snap/bin/docker",                      // Ubuntu Snap
	}

	// First, try the standard PATH lookup
	if path, err := exec.LookPath("docker"); err == nil {
		klog.V(3).Infof("Found docker via PATH: %s", path)
		return path
	}

	// Then check common installation paths
	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Additional check: ensure it's executable
			if info.Mode()&0111 != 0 {
				klog.V(3).Infof("Found docker at: %s", path)
				return path
			}
		}
	}

	// For OpenShift/container environments, check if docker is available via which command
	if cmd := exec.Command("which", "docker"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			path := strings.TrimSpace(string(output))
			if path != "" {
				klog.V(3).Infof("Found docker via which: %s", path)
				return path
			}
		}
	}

	// Check environment variable override
	if envPath := os.Getenv("DOCKER_BINARY"); envPath != "" {
		if info, err := os.Stat(envPath); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			klog.V(3).Infof("Found docker via DOCKER_BINARY env var: %s", envPath)
			return envPath
		}
	}

	klog.V(2).Info("Docker binary not found in any common location")
	return ""
}

// NewDockerRuntime creates a new DockerRuntime instance
func NewDockerRuntime() (*DockerRuntime, error) {
	binaryPath := findDockerBinary()
	if binaryPath == "" {
		return nil, fmt.Errorf("docker binary not found in PATH or common locations")
	}

	return &DockerRuntime{
		binaryPath: binaryPath,
	}, nil
}

// IsAvailable checks if Docker is available
func (d *DockerRuntime) IsAvailable() bool {
	return findDockerBinary() != ""
}

// Name returns the runtime name
func (d *DockerRuntime) Name() string {
	return "docker"
}

// Version gets the version of Docker
func (d *DockerRuntime) Version(ctx context.Context) (*RuntimeVersion, error) {
	cmd := exec.CommandContext(ctx, d.binaryPath, "version", "--format", "json")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}

	var versionInfo struct {
		Client struct {
			Version    string `json:"Version"`
			APIVersion string `json:"APIVersion"`
			GitCommit  string `json:"GitCommit"`
			GoVersion  string `json:"GoVersion"`
			Os         string `json:"Os"`
			Arch       string `json:"Arch"`
		} `json:"Client"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &versionInfo); err != nil {
		return nil, fmt.Errorf("failed to parse version JSON: %w", err)
	}

	return &RuntimeVersion{
		Version:    versionInfo.Client.Version,
		APIVersion: versionInfo.Client.APIVersion,
		GitCommit:  versionInfo.Client.GitCommit,
		GoVersion:  versionInfo.Client.GoVersion,
		Os:         versionInfo.Client.Os,
		Arch:       versionInfo.Client.Arch,
	}, nil
}

// Info gets information about the Docker runtime
func (d *DockerRuntime) Info(ctx context.Context) (*RuntimeInfo, error) {
	cmd := exec.CommandContext(ctx, d.binaryPath, "info", "--format", "json")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get info: %w", err)
	}

	var infoData struct {
		ServerVersion   string `json:"ServerVersion"`
		Driver          string `json:"Driver"`
		DockerRootDir   string `json:"DockerRootDir"`
		Name            string `json:"Name"`
		KernelVersion   string `json:"KernelVersion"`
		OperatingSystem string `json:"OperatingSystem"`
		Architecture    string `json:"Architecture"`
		NCPU            int    `json:"NCPU"`
		MemTotal        int64  `json:"MemTotal"`
		Containers      int    `json:"Containers"`
		Images          int    `json:"Images"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &infoData); err != nil {
		return nil, fmt.Errorf("failed to parse info JSON: %w", err)
	}

	return &RuntimeInfo{
		Name:    "docker",
		Version: infoData.ServerVersion,
		Storage: &StorageInfo{
			Driver:  infoData.Driver,
			Root:    infoData.DockerRootDir,
			RunRoot: infoData.DockerRootDir + "/runtimes",
		},
		Host: &HostInfo{
			Hostname:     infoData.Name,
			Kernel:       infoData.KernelVersion,
			OS:           infoData.OperatingSystem,
			Architecture: infoData.Architecture,
			CPUs:         infoData.NCPU,
			Memory:       infoData.MemTotal,
		},
		ContainersCount: infoData.Containers,
		ImagesCount:     infoData.Images,
	}, nil
}

// BuildImage builds a container image using Docker
func (d *DockerRuntime) BuildImage(ctx context.Context, opts BuildOptions) (*BuildResult, error) {
	args := []string{"build"}

	if opts.Dockerfile != "" {
		args = append(args, "-f", opts.Dockerfile)
	}

	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	if opts.Target != "" {
		args = append(args, "--target", opts.Target)
	}

	if opts.NoCache {
		args = append(args, "--no-cache")
	}

	if opts.Pull {
		args = append(args, "--pull")
	}

	// Add build args
	for key, value := range opts.BuildArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}

	// Add labels
	for key, value := range opts.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", key, value))
	}

	// Add tag and context
	args = append(args, "-t", opts.ImageTag, opts.ContextDir)

	cmd := exec.CommandContext(ctx, d.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &BuildResult{
		ImageTag: opts.ImageTag,
		Duration: duration,
		Success:  err == nil,
		Output:   stdout.String(),
	}

	if err != nil {
		result.Error = fmt.Errorf("build failed: %v\nStderr: %s", err, stderr.String())
		return result, fmt.Errorf("docker build failed: %w", err)
	}

	return result, nil
}

// Implement other required methods with basic Docker commands...
// For brevity, I'll add the essential ones. You can extend this as needed.

func (d *DockerRuntime) PushImage(ctx context.Context, opts PushOptions) (*PushResult, error) {
	return nil, fmt.Errorf("docker push not implemented yet")
}

func (d *DockerRuntime) PullImage(ctx context.Context, opts PullOptions) (*PullResult, error) {
	return nil, fmt.Errorf("docker pull not implemented yet")
}

func (d *DockerRuntime) ListImages(ctx context.Context, opts ListImagesOptions) ([]*Image, error) {
	return nil, fmt.Errorf("docker images list not implemented yet")
}

func (d *DockerRuntime) InspectImage(ctx context.Context, imageID string) (*ImageInspect, error) {
	return nil, fmt.Errorf("docker image inspect not implemented yet")
}

func (d *DockerRuntime) RemoveImage(ctx context.Context, imageID string, force bool) error {
	return fmt.Errorf("docker image remove not implemented yet")
}

func (d *DockerRuntime) TagImage(ctx context.Context, sourceImage, targetImage string) error {
	return fmt.Errorf("docker image tag not implemented yet")
}

func (d *DockerRuntime) RunContainer(ctx context.Context, opts RunOptions) (*RunResult, error) {
	return nil, fmt.Errorf("docker run not implemented yet")
}

func (d *DockerRuntime) ListContainers(ctx context.Context, opts ListContainersOptions) ([]*Container, error) {
	return nil, fmt.Errorf("docker ps not implemented yet")
}

func (d *DockerRuntime) InspectContainer(ctx context.Context, containerID string) (*ContainerInspect, error) {
	return nil, fmt.Errorf("docker inspect not implemented yet")
}

func (d *DockerRuntime) StopContainer(ctx context.Context, containerID string, timeout *time.Duration) error {
	return fmt.Errorf("docker stop not implemented yet")
}

func (d *DockerRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	return fmt.Errorf("docker rm not implemented yet")
}

func (d *DockerRuntime) ContainerLogs(ctx context.Context, containerID string, opts LogsOptions) (io.ReadCloser, error) {
	return nil, fmt.Errorf("docker logs not implemented yet")
}

func (d *DockerRuntime) ExecContainer(ctx context.Context, containerID string, opts ExecOptions) (*ExecResult, error) {
	return nil, fmt.Errorf("docker exec not implemented yet")
}
