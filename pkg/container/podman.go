package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// PodmanRuntime implements ContainerRuntime interface for Podman
type PodmanRuntime struct {
	binaryPath string
}

// findPodmanBinary searches for podman binary in multiple locations
// This handles different deployment scenarios including OpenShift environments
func findPodmanBinary() string {
	// Common locations where podman might be installed
	commonPaths := []string{
		"/usr/bin/podman",                       // Standard Linux location
		"/usr/local/bin/podman",                 // Alternative Linux location
		"/opt/podman/bin/podman",                // macOS Podman Desktop
		"/bin/podman",                           // Some minimal containers
		"/usr/sbin/podman",                      // Some system installations
		"/opt/homebrew/bin/podman",              // macOS Homebrew
		"/home/linuxbrew/.linuxbrew/bin/podman", // Linux Homebrew
	}

	// First, try the standard PATH lookup
	if path, err := exec.LookPath("podman"); err == nil {
		klog.V(3).Infof("Found podman via PATH: %s", path)
		return path
	}

	// Then check common installation paths
	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Additional check: ensure it's executable
			if info.Mode()&0111 != 0 {
				klog.V(3).Infof("Found podman at: %s", path)
				return path
			}
		}
	}

	// For OpenShift/container environments, check if podman is available via which command
	if cmd := exec.Command("which", "podman"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			path := strings.TrimSpace(string(output))
			if path != "" {
				klog.V(3).Infof("Found podman via which: %s", path)
				return path
			}
		}
	}

	// Check environment variable override
	if envPath := os.Getenv("PODMAN_BINARY"); envPath != "" {
		if info, err := os.Stat(envPath); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			klog.V(3).Infof("Found podman via PODMAN_BINARY env var: %s", envPath)
			return envPath
		}
	}

	klog.V(2).Info("Podman binary not found in any common location")
	return ""
}

// NewPodmanRuntime creates a new PodmanRuntime instance
func NewPodmanRuntime() (*PodmanRuntime, error) {
	binaryPath := findPodmanBinary()
	if binaryPath == "" {
		return nil, fmt.Errorf("podman binary not found in PATH or common locations")
	}

	return &PodmanRuntime{
		binaryPath: binaryPath,
	}, nil
}

// IsAvailable checks if Podman is available
func (p *PodmanRuntime) IsAvailable() bool {
	return findPodmanBinary() != ""
}

// Name returns the runtime name
func (p *PodmanRuntime) Name() string {
	return "podman"
}

// BuildImage builds a container image using Podman
func (p *PodmanRuntime) BuildImage(ctx context.Context, opts BuildOptions) (*BuildResult, error) {
	args := []string{"build"}

	if opts.Dockerfile != "" {
		args = append(args, "-f", opts.Dockerfile)
	}

	if opts.ImageTag != "" {
		args = append(args, "-t", opts.ImageTag)
	}

	if opts.NoCache {
		args = append(args, "--no-cache")
	}

	if opts.Pull {
		args = append(args, "--pull")
	}

	if opts.Quiet {
		args = append(args, "--quiet")
	}

	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	if opts.Target != "" {
		args = append(args, "--target", opts.Target)
	}

	for key, value := range opts.BuildArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}

	for key, value := range opts.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", key, value))
	}

	args = append(args, opts.ContextDir)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &BuildResult{
		ImageTag: opts.ImageTag,
		Duration: duration,
		Output:   stdout.String() + stderr.String(),
		Success:  err == nil,
		Error:    err,
	}

	if err == nil && opts.ImageTag != "" {
		// Try to get the image ID
		if imageID, inspectErr := p.getImageID(ctx, opts.ImageTag); inspectErr == nil {
			result.ImageID = imageID
		}
	}

	return result, nil
}

// PushImage pushes a container image using Podman
func (p *PodmanRuntime) PushImage(ctx context.Context, opts PushOptions) (*PushResult, error) {
	args := []string{"push"}

	if opts.SkipTLSVerify {
		args = append(args, "--tls-verify=false")
	}

	if opts.Quiet {
		args = append(args, "--quiet")
	}

	if opts.Username != "" && opts.Password != "" {
		args = append(args, "--creds", fmt.Sprintf("%s:%s", opts.Username, opts.Password))
	}

	targetImage := opts.ImageTag
	if opts.Registry != "" && !strings.Contains(opts.ImageTag, opts.Registry) {
		// If registry is specified and not already in the image tag, prepend it
		parts := strings.Split(opts.ImageTag, "/")
		imageName := parts[len(parts)-1]
		targetImage = strings.TrimSuffix(opts.Registry, "/") + "/" + imageName

		// Tag the image first
		if err := p.TagImage(ctx, opts.ImageTag, targetImage); err != nil {
			return &PushResult{
				ImageTag: opts.ImageTag,
				Registry: opts.Registry,
				Success:  false,
				Error:    fmt.Errorf("failed to tag image: %w", err),
			}, nil
		}
	}

	args = append(args, targetImage)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	return &PushResult{
		ImageTag: targetImage,
		Registry: opts.Registry,
		Duration: duration,
		Output:   stdout.String() + stderr.String(),
		Success:  err == nil,
		Error:    err,
	}, nil
}

// PullImage pulls a container image using Podman
func (p *PodmanRuntime) PullImage(ctx context.Context, opts PullOptions) (*PullResult, error) {
	args := []string{"pull"}

	if opts.SkipTLSVerify {
		args = append(args, "--tls-verify=false")
	}

	if opts.Quiet {
		args = append(args, "--quiet")
	}

	if opts.Username != "" && opts.Password != "" {
		args = append(args, "--creds", fmt.Sprintf("%s:%s", opts.Username, opts.Password))
	}

	args = append(args, opts.ImageTag)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &PullResult{
		ImageTag: opts.ImageTag,
		Duration: duration,
		Output:   stdout.String() + stderr.String(),
		Success:  err == nil,
		Error:    err,
	}

	if err == nil {
		// Try to get the image ID
		if imageID, inspectErr := p.getImageID(ctx, opts.ImageTag); inspectErr == nil {
			result.ImageID = imageID
		}
	}

	return result, nil
}

// ListImages lists container images using Podman
func (p *PodmanRuntime) ListImages(ctx context.Context, opts ListImagesOptions) ([]*Image, error) {
	args := []string{"images", "--format", "json"}

	if opts.All {
		args = append(args, "--all")
	}

	if opts.Filter != "" {
		args = append(args, "--filter", opts.Filter)
	}

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var podmanImages []struct {
		ID         string            `json:"Id"`
		Repository string            `json:"Repository"`
		Tag        string            `json:"Tag"`
		Digest     string            `json:"Digest"`
		Created    int64             `json:"Created"`
		Size       int64             `json:"Size"`
		Labels     map[string]string `json:"Labels"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &podmanImages); err != nil {
		return nil, fmt.Errorf("failed to parse images JSON: %w", err)
	}

	images := make([]*Image, 0, len(podmanImages))
	for _, img := range podmanImages {
		image := &Image{
			ID:         img.ID,
			Repository: img.Repository,
			Tag:        img.Tag,
			Digest:     img.Digest,
			Created:    time.Unix(img.Created, 0),
			Size:       img.Size,
			Labels:     img.Labels,
		}
		images = append(images, image)
	}

	return images, nil
}

// InspectImage inspects a container image using Podman
func (p *PodmanRuntime) InspectImage(ctx context.Context, imageID string) (*ImageInspect, error) {
	cmd := exec.CommandContext(ctx, p.binaryPath, "inspect", "--format", "json", imageID)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	var podmanImages []struct {
		ID           string            `json:"Id"`
		RepoTags     []string          `json:"RepoTags"`
		RepoDigests  []string          `json:"RepoDigests"`
		Created      time.Time         `json:"Created"`
		Size         int64             `json:"Size"`
		VirtualSize  int64             `json:"VirtualSize"`
		Labels       map[string]string `json:"Labels"`
		Architecture string            `json:"Architecture"`
		Os           string            `json:"Os"`
		Config       *ImageConfig      `json:"Config"`
		RootFS       *RootFS           `json:"RootFS"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &podmanImages); err != nil {
		return nil, fmt.Errorf("failed to parse image inspect JSON: %w", err)
	}

	if len(podmanImages) == 0 {
		return nil, fmt.Errorf("image not found")
	}

	img := podmanImages[0]
	return &ImageInspect{
		ID:           img.ID,
		RepoTags:     img.RepoTags,
		RepoDigests:  img.RepoDigests,
		Created:      img.Created,
		Size:         img.Size,
		VirtualSize:  img.VirtualSize,
		Labels:       img.Labels,
		Architecture: img.Architecture,
		Os:           img.Os,
		Config:       img.Config,
		RootFS:       img.RootFS,
	}, nil
}

// RemoveImage removes a container image using Podman
func (p *PodmanRuntime) RemoveImage(ctx context.Context, imageID string, force bool) error {
	args := []string{"rmi"}

	if force {
		args = append(args, "--force")
	}

	args = append(args, imageID)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove image: %w", err)
	}

	return nil
}

// TagImage tags a container image using Podman
func (p *PodmanRuntime) TagImage(ctx context.Context, sourceImage, targetImage string) error {
	cmd := exec.CommandContext(ctx, p.binaryPath, "tag", sourceImage, targetImage)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to tag image: %w", err)
	}

	return nil
}

// RunContainer runs a container using Podman
func (p *PodmanRuntime) RunContainer(ctx context.Context, opts RunOptions) (*RunResult, error) {
	args := []string{"run"}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}

	if opts.Detach {
		args = append(args, "--detach")
	}

	if opts.Remove {
		args = append(args, "--rm")
	}

	if opts.Interactive {
		args = append(args, "--interactive")
	}

	if opts.TTY {
		args = append(args, "--tty")
	}

	if opts.Privileged {
		args = append(args, "--privileged")
	}

	if opts.ReadOnly {
		args = append(args, "--read-only")
	}

	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}

	if opts.WorkingDir != "" {
		args = append(args, "--workdir", opts.WorkingDir)
	}

	if opts.RestartPolicy != "" {
		args = append(args, "--restart", opts.RestartPolicy)
	}

	for _, env := range opts.Env {
		args = append(args, "--env", env)
	}

	for _, port := range opts.Ports {
		portMapping := fmt.Sprintf("%d:%d", port.HostPort, port.ContainerPort)
		if port.Protocol != "" {
			portMapping += "/" + port.Protocol
		}
		if port.HostIP != "" {
			portMapping = port.HostIP + ":" + portMapping
		}
		args = append(args, "--publish", portMapping)
	}

	for _, volume := range opts.Volumes {
		volumeMapping := fmt.Sprintf("%s:%s", volume.HostPath, volume.ContainerPath)
		if volume.Mode != "" {
			volumeMapping += ":" + volume.Mode
		}
		args = append(args, "--volume", volumeMapping)
	}

	for key, value := range opts.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", key, value))
	}

	args = append(args, opts.Image)

	if len(opts.Entrypoint) > 0 {
		args = append(args, "--entrypoint")
		args = append(args, opts.Entrypoint...)
	}

	if len(opts.Command) > 0 {
		args = append(args, opts.Command...)
	}

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &RunResult{
		Name:     opts.Name,
		Duration: duration,
		Output:   stdout.String() + stderr.String(),
		Success:  err == nil,
		Error:    err,
	}

	if err == nil && opts.Detach {
		// For detached containers, the output should contain the container ID
		result.ContainerID = strings.TrimSpace(stdout.String())
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitError.ExitCode()
	}

	return result, nil
}

// ListContainers lists containers using Podman
func (p *PodmanRuntime) ListContainers(ctx context.Context, opts ListContainersOptions) ([]*Container, error) {
	args := []string{"ps", "--format", "json"}

	if opts.All {
		args = append(args, "--all")
	}

	if opts.Size {
		args = append(args, "--size")
	}

	if opts.Filter != "" {
		args = append(args, "--filter", opts.Filter)
	}

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var podmanContainers []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		Command string            `json:"Command"`
		Created int64             `json:"Created"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Ports   []PortMapping     `json:"Ports"`
		Labels  map[string]string `json:"Labels"`
		Size    int64             `json:"Size"`
		Mounts  []MountPoint      `json:"Mounts"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &podmanContainers); err != nil {
		return nil, fmt.Errorf("failed to parse containers JSON: %w", err)
	}

	containers := make([]*Container, 0, len(podmanContainers))
	for _, ctr := range podmanContainers {
		container := &Container{
			ID:      ctr.ID,
			Names:   ctr.Names,
			Image:   ctr.Image,
			ImageID: ctr.ImageID,
			Command: ctr.Command,
			Created: time.Unix(ctr.Created, 0),
			State:   ctr.State,
			Status:  ctr.Status,
			Ports:   ctr.Ports,
			Labels:  ctr.Labels,
			Size:    ctr.Size,
			Mounts:  ctr.Mounts,
		}
		containers = append(containers, container)
	}

	return containers, nil
}

// InspectContainer inspects a container using Podman
func (p *PodmanRuntime) InspectContainer(ctx context.Context, containerID string) (*ContainerInspect, error) {
	cmd := exec.CommandContext(ctx, p.binaryPath, "inspect", "--format", "json", containerID)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	var podmanContainers []struct {
		ID              string                    `json:"Id"`
		Name            string                    `json:"Name"`
		Image           string                    `json:"Image"`
		ImageID         string                    `json:"ImageID"`
		Command         []string                  `json:"Command"`
		Created         time.Time                 `json:"Created"`
		State           *ContainerState           `json:"State"`
		Config          *ContainerConfig          `json:"Config"`
		HostConfig      *ContainerHostConfig      `json:"HostConfig"`
		NetworkSettings *ContainerNetworkSettings `json:"NetworkSettings"`
		Mounts          []MountPoint              `json:"Mounts"`
		Labels          map[string]string         `json:"Labels"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &podmanContainers); err != nil {
		return nil, fmt.Errorf("failed to parse container inspect JSON: %w", err)
	}

	if len(podmanContainers) == 0 {
		return nil, fmt.Errorf("container not found")
	}

	ctr := podmanContainers[0]
	return &ContainerInspect{
		ID:              ctr.ID,
		Name:            ctr.Name,
		Image:           ctr.Image,
		ImageID:         ctr.ImageID,
		Command:         ctr.Command,
		Created:         ctr.Created,
		State:           ctr.State,
		Config:          ctr.Config,
		HostConfig:      ctr.HostConfig,
		NetworkSettings: ctr.NetworkSettings,
		Mounts:          ctr.Mounts,
		Labels:          ctr.Labels,
	}, nil
}

// StopContainer stops a container using Podman
func (p *PodmanRuntime) StopContainer(ctx context.Context, containerID string, timeout *time.Duration) error {
	args := []string{"stop"}

	if timeout != nil {
		args = append(args, "--time", strconv.Itoa(int(timeout.Seconds())))
	}

	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

// RemoveContainer removes a container using Podman
func (p *PodmanRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	args := []string{"rm"}

	if force {
		args = append(args, "--force")
	}

	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	return nil
}

// ContainerLogs gets logs from a container using Podman
func (p *PodmanRuntime) ContainerLogs(ctx context.Context, containerID string, opts LogsOptions) (io.ReadCloser, error) {
	args := []string{"logs"}

	if opts.Follow {
		args = append(args, "--follow")
	}

	if opts.Since != "" {
		args = append(args, "--since", opts.Since)
	}

	if opts.Until != "" {
		args = append(args, "--until", opts.Until)
	}

	if opts.Timestamps {
		args = append(args, "--timestamps")
	}

	if opts.Tail != "" {
		args = append(args, "--tail", opts.Tail)
	}

	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start logs command: %w", err)
	}

	// Return a ReadCloser that will wait for the command to finish when closed
	return &cmdReadCloser{
		ReadCloser: stdout,
		cmd:        cmd,
	}, nil
}

// ExecContainer executes a command in a container using Podman
func (p *PodmanRuntime) ExecContainer(ctx context.Context, containerID string, opts ExecOptions) (*ExecResult, error) {
	args := []string{"exec"}

	if opts.Interactive {
		args = append(args, "--interactive")
	}

	if opts.TTY {
		args = append(args, "--tty")
	}

	if opts.Privileged {
		args = append(args, "--privileged")
	}

	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}

	if opts.WorkingDir != "" {
		args = append(args, "--workdir", opts.WorkingDir)
	}

	for _, env := range opts.Env {
		args = append(args, "--env", env)
	}

	args = append(args, containerID)
	args = append(args, opts.Command...)

	cmd := exec.CommandContext(ctx, p.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ExecResult{
		Output: stdout.String(),
		Error:  stderr.String(),
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitError.ExitCode()
	} else if err != nil {
		result.ExitCode = 1
		if result.Error == "" {
			result.Error = err.Error()
		}
	}

	return result, nil
}

// Version gets the version of Podman
func (p *PodmanRuntime) Version(ctx context.Context) (*RuntimeVersion, error) {
	cmd := exec.CommandContext(ctx, p.binaryPath, "version", "--format", "json")

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

// Info gets information about the Podman runtime
func (p *PodmanRuntime) Info(ctx context.Context) (*RuntimeInfo, error) {
	cmd := exec.CommandContext(ctx, p.binaryPath, "info", "--format", "json")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get info: %w", err)
	}

	var infoData struct {
		Version struct {
			Version string `json:"Version"`
		} `json:"version"`
		Store struct {
			GraphDriverName string            `json:"graphDriverName"`
			GraphRoot       string            `json:"graphRoot"`
			RunRoot         string            `json:"runRoot"`
			GraphStatus     map[string]string `json:"graphStatus"`
		} `json:"store"`
		Host struct {
			Hostname string `json:"hostname"`
			Kernel   string `json:"kernel"`
			Os       string `json:"os"`
			Arch     string `json:"arch"`
			CPUs     int    `json:"cpus"`
			MemTotal int64  `json:"memTotal"`
		} `json:"host"`
		Registries struct {
			Search []string `json:"search"`
		} `json:"registries"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &infoData); err != nil {
		return nil, fmt.Errorf("failed to parse info JSON: %w", err)
	}

	// Get container and image counts
	containers, _ := p.ListContainers(ctx, ListContainersOptions{All: true})
	images, _ := p.ListImages(ctx, ListImagesOptions{All: true})

	return &RuntimeInfo{
		Name:    "podman",
		Version: infoData.Version.Version,
		Storage: &StorageInfo{
			Driver:      infoData.Store.GraphDriverName,
			Root:        infoData.Store.GraphRoot,
			RunRoot:     infoData.Store.RunRoot,
			GraphStatus: infoData.Store.GraphStatus,
		},
		Host: &HostInfo{
			Hostname:     infoData.Host.Hostname,
			Kernel:       infoData.Host.Kernel,
			OS:           infoData.Host.Os,
			Architecture: infoData.Host.Arch,
			CPUs:         infoData.Host.CPUs,
			Memory:       infoData.Host.MemTotal,
		},
		Registries:      map[string]string{"search": strings.Join(infoData.Registries.Search, ", ")},
		ContainersCount: len(containers),
		ImagesCount:     len(images),
	}, nil
}

// getImageID gets the image ID for a given image tag
func (p *PodmanRuntime) getImageID(ctx context.Context, imageTag string) (string, error) {
	cmd := exec.CommandContext(ctx, p.binaryPath, "images", "--format", "{{.ID}}", imageTag)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}

// cmdReadCloser wraps a ReadCloser and ensures the command finishes when closed
type cmdReadCloser struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (c *cmdReadCloser) Close() error {
	if err := c.ReadCloser.Close(); err != nil {
		klog.V(5).Infof("Error closing stdout pipe: %v", err)
	}

	if err := c.cmd.Wait(); err != nil {
		klog.V(5).Infof("Command finished with error: %v", err)
	}

	return nil
}
