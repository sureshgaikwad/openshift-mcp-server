package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/containers/kubernetes-mcp-server/pkg/container"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// initContainers initializes container-related MCP tools
func (s *Server) initContainers() []server.ServerTool {
	return []server.ServerTool{
		// Image management tools
		{Tool: mcp.NewTool("container_build_image",
			mcp.WithDescription("Build a container image using the available container runtime (Podman/Docker)"),
			mcp.WithString("imageTag", mcp.Description("Image tag to build (e.g., quay.io/user/image:v1)"), mcp.Required()),
			mcp.WithString("dockerfile", mcp.Description("Path to Dockerfile (default: Dockerfile)")),
			mcp.WithString("context", mcp.Description("Build context directory (default: current directory)")),
			mcp.WithString("platform", mcp.Description("Target platform (e.g., linux/amd64, linux/arm64)")),
			mcp.WithString("target", mcp.Description("Build target stage in multi-stage Dockerfile")),
			mcp.WithBoolean("noCache", mcp.Description("Do not use cache when building")),
			mcp.WithBoolean("pull", mcp.Description("Always pull base images")),
			mcp.WithBoolean("quiet", mcp.Description("Suppress build output")),
			mcp.WithObject("buildArgs", mcp.Description("Build-time variables (key-value pairs)")),
			mcp.WithObject("labels", mcp.Description("Image labels (key-value pairs)")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Build Image"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerBuildImage},

		{Tool: mcp.NewTool("container_push_image",
			mcp.WithDescription("Push a container image to a registry using the available container runtime"),
			mcp.WithString("imageTag", mcp.Description("Image tag to push (e.g., quay.io/user/image:v1)"), mcp.Required()),
			mcp.WithString("registry", mcp.Description("Registry URL (e.g., quay.io, registry.redhat.io)")),
			mcp.WithString("username", mcp.Description("Registry username")),
			mcp.WithString("password", mcp.Description("Registry password")),
			mcp.WithBoolean("skipTlsVerify", mcp.Description("Skip TLS verification")),
			mcp.WithBoolean("quiet", mcp.Description("Suppress push output")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Push Image"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerPushImage},

		{Tool: mcp.NewTool("container_pull_image",
			mcp.WithDescription("Pull a container image from a registry using the available container runtime"),
			mcp.WithString("imageTag", mcp.Description("Image tag to pull (e.g., quay.io/user/image:v1)"), mcp.Required()),
			mcp.WithString("registry", mcp.Description("Registry URL (e.g., quay.io, registry.redhat.io)")),
			mcp.WithString("username", mcp.Description("Registry username")),
			mcp.WithString("password", mcp.Description("Registry password")),
			mcp.WithBoolean("skipTlsVerify", mcp.Description("Skip TLS verification")),
			mcp.WithBoolean("quiet", mcp.Description("Suppress pull output")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Pull Image"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerPullImage},

		{Tool: mcp.NewTool("container_list_images",
			mcp.WithDescription("List container images available on the local system"),
			mcp.WithBoolean("all", mcp.Description("Show all images including intermediate images")),
			mcp.WithString("filter", mcp.Description("Filter images (e.g., 'dangling=true', 'label=key=value')")),
			mcp.WithBoolean("quiet", mcp.Description("Only show image IDs")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: List Images"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerListImages},

		{Tool: mcp.NewTool("container_inspect_image",
			mcp.WithDescription("Inspect a container image and show detailed information"),
			mcp.WithString("imageId", mcp.Description("Image ID or tag to inspect"), mcp.Required()),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Inspect Image"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerInspectImage},

		{Tool: mcp.NewTool("container_remove_image",
			mcp.WithDescription("Remove a container image from the local system"),
			mcp.WithString("imageId", mcp.Description("Image ID or tag to remove"), mcp.Required()),
			mcp.WithBoolean("force", mcp.Description("Force removal of the image")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Remove Image"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(true),
		), Handler: s.containerRemoveImage},

		{Tool: mcp.NewTool("container_tag_image",
			mcp.WithDescription("Tag a container image with a new name and tag"),
			mcp.WithString("sourceImage", mcp.Description("Source image ID or tag"), mcp.Required()),
			mcp.WithString("targetImage", mcp.Description("Target image name and tag"), mcp.Required()),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Tag Image"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerTagImage},

		// Container management tools
		{Tool: mcp.NewTool("container_run",
			mcp.WithDescription("Run a container from an image using the available container runtime"),
			mcp.WithString("image", mcp.Description("Container image to run"), mcp.Required()),
			mcp.WithString("name", mcp.Description("Container name")),
			mcp.WithArray("command", mcp.Description("Command to run in the container"), mcp.WithStringItems()),
			mcp.WithArray("entrypoint", mcp.Description("Override the default entrypoint"), mcp.WithStringItems()),
			mcp.WithArray("env", mcp.Description("Environment variables (e.g., ['KEY=value'])"), mcp.WithStringItems()),
			mcp.WithString("workingDir", mcp.Description("Working directory inside the container")),
			mcp.WithString("user", mcp.Description("User to run the container as")),
			mcp.WithArray("ports", mcp.Description("Port mappings (e.g., ['8080:80'])"), mcp.WithStringItems()),
			mcp.WithArray("volumes", mcp.Description("Volume mappings (e.g., ['/host:/container'])"), mcp.WithStringItems()),
			mcp.WithObject("labels", mcp.Description("Container labels (key-value pairs)")),
			mcp.WithBoolean("detach", mcp.Description("Run container in detached mode")),
			mcp.WithBoolean("remove", mcp.Description("Automatically remove container when it exits")),
			mcp.WithBoolean("interactive", mcp.Description("Keep STDIN open")),
			mcp.WithBoolean("tty", mcp.Description("Allocate a pseudo-TTY")),
			mcp.WithBoolean("privileged", mcp.Description("Give extended privileges to the container")),
			mcp.WithBoolean("readOnly", mcp.Description("Mount the container's root filesystem as read-only")),
			mcp.WithString("restartPolicy", mcp.Description("Restart policy (no, always, on-failure, unless-stopped)")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Run"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerRun},

		{Tool: mcp.NewTool("container_list",
			mcp.WithDescription("List containers on the local system"),
			mcp.WithBoolean("all", mcp.Description("Show all containers including stopped ones")),
			mcp.WithString("filter", mcp.Description("Filter containers (e.g., 'status=running', 'name=myapp')")),
			mcp.WithBoolean("quiet", mcp.Description("Only show container IDs")),
			mcp.WithBoolean("size", mcp.Description("Display container sizes")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: List"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerList},

		{Tool: mcp.NewTool("container_inspect",
			mcp.WithDescription("Inspect a container and show detailed information"),
			mcp.WithString("containerId", mcp.Description("Container ID or name to inspect"), mcp.Required()),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Inspect"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerInspect},

		{Tool: mcp.NewTool("container_stop",
			mcp.WithDescription("Stop a running container"),
			mcp.WithString("containerId", mcp.Description("Container ID or name to stop"), mcp.Required()),
			mcp.WithNumber("timeout", mcp.Description("Seconds to wait before killing the container")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Stop"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerStop},

		{Tool: mcp.NewTool("container_remove",
			mcp.WithDescription("Remove a container from the local system"),
			mcp.WithString("containerId", mcp.Description("Container ID or name to remove"), mcp.Required()),
			mcp.WithBoolean("force", mcp.Description("Force removal of the container")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Remove"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(true),
		), Handler: s.containerRemove},

		{Tool: mcp.NewTool("container_logs",
			mcp.WithDescription("Get logs from a container"),
			mcp.WithString("containerId", mcp.Description("Container ID or name to get logs from"), mcp.Required()),
			mcp.WithBoolean("follow", mcp.Description("Follow log output")),
			mcp.WithString("since", mcp.Description("Show logs since timestamp (e.g., '2023-01-01T00:00:00Z' or '1h')")),
			mcp.WithString("until", mcp.Description("Show logs until timestamp")),
			mcp.WithBoolean("timestamps", mcp.Description("Show timestamps")),
			mcp.WithString("tail", mcp.Description("Number of lines to show from the end of the logs")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Logs"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerLogs},

		{Tool: mcp.NewTool("container_exec",
			mcp.WithDescription("Execute a command in a running container"),
			mcp.WithString("containerId", mcp.Description("Container ID or name to execute command in"), mcp.Required()),
			mcp.WithArray("command", mcp.Description("Command to execute"), mcp.WithStringItems(), mcp.Required()),
			mcp.WithString("user", mcp.Description("User to run the command as")),
			mcp.WithString("workingDir", mcp.Description("Working directory for the command")),
			mcp.WithArray("env", mcp.Description("Environment variables (e.g., ['KEY=value'])"), mcp.WithStringItems()),
			mcp.WithBoolean("privileged", mcp.Description("Give extended privileges to the command")),
			mcp.WithBoolean("interactive", mcp.Description("Keep STDIN open")),
			mcp.WithBoolean("tty", mcp.Description("Allocate a pseudo-TTY")),
			mcp.WithString("runtime", mcp.Description("Container runtime to use (podman, docker). Uses primary if not specified")),
			mcp.WithTitleAnnotation("Container: Exec"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerExec},

		// Runtime information tools
		{Tool: mcp.NewTool("container_runtime_info",
			mcp.WithDescription("Get information about available container runtimes"),
			mcp.WithString("runtime", mcp.Description("Specific runtime to get info for (podman, docker). Shows all if not specified")),
			mcp.WithTitleAnnotation("Container: Runtime Info"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerRuntimeInfo},

		{Tool: mcp.NewTool("container_runtime_version",
			mcp.WithDescription("Get version information about available container runtimes"),
			mcp.WithString("runtime", mcp.Description("Specific runtime to get version for (podman, docker). Shows all if not specified")),
			mcp.WithTitleAnnotation("Container: Runtime Version"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		), Handler: s.containerRuntimeVersion},
	}
}

// Container runtime manager (initialized in constructor)
func (s *Server) getContainerManager() *container.Manager {
	return s.containerManager
}

// Helper function to get the specified runtime or primary runtime
func (s *Server) getRuntime(runtimeName string) (container.ContainerRuntime, error) {
	manager := s.getContainerManager()

	if runtimeName != "" {
		return manager.GetRuntime(runtimeName)
	}

	return manager.GetPrimaryRuntime()
}

// containerBuildImage builds a container image
func (s *Server) containerBuildImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	imageTag, ok := args["imageTag"].(string)
	if !ok || imageTag == "" {
		return NewTextResult("", fmt.Errorf("imageTag is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Build options
	opts := container.BuildOptions{
		ImageTag:   imageTag,
		ContextDir: ".",
		Dockerfile: "Dockerfile",
	}

	if dockerfile, ok := args["dockerfile"].(string); ok && dockerfile != "" {
		opts.Dockerfile = dockerfile
	}

	if contextDir, ok := args["context"].(string); ok && contextDir != "" {
		opts.ContextDir = contextDir
	}

	if platform, ok := args["platform"].(string); ok && platform != "" {
		opts.Platform = platform
	}

	if target, ok := args["target"].(string); ok && target != "" {
		opts.Target = target
	}

	if noCache, ok := args["noCache"].(bool); ok {
		opts.NoCache = noCache
	}

	if pull, ok := args["pull"].(bool); ok {
		opts.Pull = pull
	}

	if quiet, ok := args["quiet"].(bool); ok {
		opts.Quiet = quiet
	}

	if buildArgs, ok := args["buildArgs"].(map[string]interface{}); ok {
		opts.BuildArgs = make(map[string]string)
		for k, v := range buildArgs {
			if strVal, ok := v.(string); ok {
				opts.BuildArgs[k] = strVal
			}
		}
	}

	if labels, ok := args["labels"].(map[string]interface{}); ok {
		opts.Labels = make(map[string]string)
		for k, v := range labels {
			if strVal, ok := v.(string); ok {
				opts.Labels[k] = strVal
			}
		}
	}

	// Execute build
	result, err := runtime.BuildImage(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("build failed: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Build Report\n"))
	output.WriteString(fmt.Sprintf("============================\n"))
	output.WriteString(fmt.Sprintf("Runtime: %s\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("Image Tag: %s\n", result.ImageTag))
	if result.ImageID != "" {
		output.WriteString(fmt.Sprintf("Image ID: %s\n", result.ImageID))
	}
	output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	output.WriteString(fmt.Sprintf("Status: %s\n", func() string {
		if result.Success {
			return "SUCCESS"
		}
		return "FAILED"
	}()))
	output.WriteString("\n")

	if result.Output != "" {
		output.WriteString("Build Output:\n")
		output.WriteString("-------------\n")
		output.WriteString(result.Output)
		output.WriteString("\n")
	}

	if result.Success {
		output.WriteString(fmt.Sprintf("✅ Container image '%s' built successfully!\n", result.ImageTag))
	} else {
		output.WriteString(fmt.Sprintf("❌ Build failed: %v\n", result.Error))
	}

	return NewTextResult(output.String(), result.Error), nil
}

// containerPushImage pushes a container image
func (s *Server) containerPushImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	imageTag, ok := args["imageTag"].(string)
	if !ok || imageTag == "" {
		return NewTextResult("", fmt.Errorf("imageTag is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Push options
	opts := container.PushOptions{
		ImageTag: imageTag,
	}

	if registry, ok := args["registry"].(string); ok && registry != "" {
		opts.Registry = registry
	}

	if username, ok := args["username"].(string); ok && username != "" {
		opts.Username = username
	}

	if password, ok := args["password"].(string); ok && password != "" {
		opts.Password = password
	}

	if skipTlsVerify, ok := args["skipTlsVerify"].(bool); ok {
		opts.SkipTLSVerify = skipTlsVerify
	}

	if quiet, ok := args["quiet"].(bool); ok {
		opts.Quiet = quiet
	}

	// Execute push
	result, err := runtime.PushImage(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("push failed: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Push Report\n"))
	output.WriteString(fmt.Sprintf("===========================\n"))
	output.WriteString(fmt.Sprintf("Runtime: %s\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("Image Tag: %s\n", result.ImageTag))
	if result.Registry != "" {
		output.WriteString(fmt.Sprintf("Registry: %s\n", result.Registry))
	}
	output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	output.WriteString("\n")

	if result.Output != "" {
		output.WriteString("Push Output:\n")
		output.WriteString("------------\n")
		output.WriteString(result.Output)
		output.WriteString("\n")
	}

	if result.Success {
		output.WriteString(fmt.Sprintf("✅ Container image '%s' pushed successfully!\n", result.ImageTag))
	} else {
		output.WriteString(fmt.Sprintf("❌ Push failed: %v\n", result.Error))
	}

	return NewTextResult(output.String(), result.Error), nil
}

// containerPullImage pulls a container image
func (s *Server) containerPullImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	imageTag, ok := args["imageTag"].(string)
	if !ok || imageTag == "" {
		return NewTextResult("", fmt.Errorf("imageTag is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Pull options
	opts := container.PullOptions{
		ImageTag: imageTag,
	}

	if registry, ok := args["registry"].(string); ok && registry != "" {
		opts.Registry = registry
	}

	if username, ok := args["username"].(string); ok && username != "" {
		opts.Username = username
	}

	if password, ok := args["password"].(string); ok && password != "" {
		opts.Password = password
	}

	if skipTlsVerify, ok := args["skipTlsVerify"].(bool); ok {
		opts.SkipTLSVerify = skipTlsVerify
	}

	if quiet, ok := args["quiet"].(bool); ok {
		opts.Quiet = quiet
	}

	// Execute pull
	result, err := runtime.PullImage(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("pull failed: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Pull Report\n"))
	output.WriteString(fmt.Sprintf("===========================\n"))
	output.WriteString(fmt.Sprintf("Runtime: %s\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("Image Tag: %s\n", result.ImageTag))
	if result.ImageID != "" {
		output.WriteString(fmt.Sprintf("Image ID: %s\n", result.ImageID))
	}
	output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	output.WriteString("\n")

	if result.Output != "" {
		output.WriteString("Pull Output:\n")
		output.WriteString("------------\n")
		output.WriteString(result.Output)
		output.WriteString("\n")
	}

	if result.Success {
		output.WriteString(fmt.Sprintf("✅ Container image '%s' pulled successfully!\n", result.ImageTag))
	} else {
		output.WriteString(fmt.Sprintf("❌ Pull failed: %v\n", result.Error))
	}

	return NewTextResult(output.String(), result.Error), nil
}

// containerListImages lists container images
func (s *Server) containerListImages(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// List options
	opts := container.ListImagesOptions{}

	if all, ok := args["all"].(bool); ok {
		opts.All = all
	}

	if filter, ok := args["filter"].(string); ok && filter != "" {
		opts.Filter = filter
	}

	if quiet, ok := args["quiet"].(bool); ok {
		opts.Quiet = quiet
	}

	// Execute list
	images, err := runtime.ListImages(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list images: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Images (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("====================\n"))
	output.WriteString(fmt.Sprintf("Found %d images\n\n", len(images)))

	if opts.Quiet {
		for _, image := range images {
			output.WriteString(fmt.Sprintf("%s\n", image.ID))
		}
	} else {
		output.WriteString(fmt.Sprintf("%-12s %-40s %-20s %-15s %s\n", "IMAGE ID", "REPOSITORY", "TAG", "SIZE", "CREATED"))
		output.WriteString(strings.Repeat("-", 100) + "\n")

		for _, image := range images {
			imageID := image.ID
			if len(imageID) > 12 {
				imageID = imageID[:12]
			}

			size := fmt.Sprintf("%.1f MB", float64(image.Size)/(1024*1024))
			created := image.Created.Format("2006-01-02 15:04")

			output.WriteString(fmt.Sprintf("%-12s %-40s %-20s %-15s %s\n",
				imageID, image.Repository, image.Tag, size, created))
		}
	}

	return NewTextResult(output.String(), nil), nil
}

// containerInspectImage inspects a container image
func (s *Server) containerInspectImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	imageID, ok := args["imageId"].(string)
	if !ok || imageID == "" {
		return NewTextResult("", fmt.Errorf("imageId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Execute inspect
	inspect, err := runtime.InspectImage(ctx, imageID)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to inspect image: %w", err)), nil
	}

	// Format result as JSON
	jsonData, err := json.MarshalIndent(inspect, "", "  ")
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to marshal inspect data: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Inspect (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=============================\n"))
	output.WriteString(fmt.Sprintf("Image: %s\n\n", imageID))
	output.WriteString(string(jsonData))

	return NewTextResult(output.String(), nil), nil
}

// containerRemoveImage removes a container image
func (s *Server) containerRemoveImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	imageID, ok := args["imageId"].(string)
	if !ok || imageID == "" {
		return NewTextResult("", fmt.Errorf("imageId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Remove options
	force, _ := args["force"].(bool)

	// Execute remove
	err = runtime.RemoveImage(ctx, imageID, force)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to remove image: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Removal (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=============================\n"))
	output.WriteString(fmt.Sprintf("✅ Image '%s' removed successfully!\n", imageID))

	return NewTextResult(output.String(), nil), nil
}

// containerTagImage tags a container image
func (s *Server) containerTagImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	sourceImage, ok := args["sourceImage"].(string)
	if !ok || sourceImage == "" {
		return NewTextResult("", fmt.Errorf("sourceImage is required")), nil
	}

	targetImage, ok := args["targetImage"].(string)
	if !ok || targetImage == "" {
		return NewTextResult("", fmt.Errorf("targetImage is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Execute tag
	err = runtime.TagImage(ctx, sourceImage, targetImage)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to tag image: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Image Tagging (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=============================\n"))
	output.WriteString(fmt.Sprintf("✅ Image '%s' tagged as '%s' successfully!\n", sourceImage, targetImage))

	return NewTextResult(output.String(), nil), nil
}

// containerRun runs a container
func (s *Server) containerRun(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	image, ok := args["image"].(string)
	if !ok || image == "" {
		return NewTextResult("", fmt.Errorf("image is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Run options
	opts := container.RunOptions{
		Image: image,
	}

	if name, ok := args["name"].(string); ok && name != "" {
		opts.Name = name
	}

	if command, ok := args["command"].([]interface{}); ok {
		opts.Command = make([]string, len(command))
		for i, v := range command {
			if strVal, ok := v.(string); ok {
				opts.Command[i] = strVal
			}
		}
	}

	if entrypoint, ok := args["entrypoint"].([]interface{}); ok {
		opts.Entrypoint = make([]string, len(entrypoint))
		for i, v := range entrypoint {
			if strVal, ok := v.(string); ok {
				opts.Entrypoint[i] = strVal
			}
		}
	}

	if env, ok := args["env"].([]interface{}); ok {
		opts.Env = make([]string, len(env))
		for i, v := range env {
			if strVal, ok := v.(string); ok {
				opts.Env[i] = strVal
			}
		}
	}

	if workingDir, ok := args["workingDir"].(string); ok && workingDir != "" {
		opts.WorkingDir = workingDir
	}

	if user, ok := args["user"].(string); ok && user != "" {
		opts.User = user
	}

	if ports, ok := args["ports"].([]interface{}); ok {
		for _, v := range ports {
			if portStr, ok := v.(string); ok {
				// Parse port mapping like "8080:80" or "127.0.0.1:8080:80/tcp"
				parts := strings.Split(portStr, ":")
				if len(parts) >= 2 {
					hostPort, _ := strconv.Atoi(parts[len(parts)-2])
					containerPortAndProtocol := parts[len(parts)-1]

					// Check for protocol
					protocol := "tcp"
					containerPortStr := containerPortAndProtocol
					if strings.Contains(containerPortAndProtocol, "/") {
						protocolParts := strings.Split(containerPortAndProtocol, "/")
						containerPortStr = protocolParts[0]
						if len(protocolParts) > 1 {
							protocol = protocolParts[1]
						}
					}

					containerPort, _ := strconv.Atoi(containerPortStr)

					portMapping := container.PortMapping{
						HostPort:      hostPort,
						ContainerPort: containerPort,
						Protocol:      protocol,
					}

					// Check for host IP
					if len(parts) == 3 {
						portMapping.HostIP = parts[0]
					}

					opts.Ports = append(opts.Ports, portMapping)
				}
			}
		}
	}

	if volumes, ok := args["volumes"].([]interface{}); ok {
		for _, v := range volumes {
			if volumeStr, ok := v.(string); ok {
				// Parse volume mapping like "/host:/container" or "/host:/container:ro"
				parts := strings.Split(volumeStr, ":")
				if len(parts) >= 2 {
					volumeMapping := container.VolumeMapping{
						HostPath:      parts[0],
						ContainerPath: parts[1],
					}

					if len(parts) > 2 {
						volumeMapping.Mode = parts[2]
					}

					opts.Volumes = append(opts.Volumes, volumeMapping)
				}
			}
		}
	}

	if labels, ok := args["labels"].(map[string]interface{}); ok {
		opts.Labels = make(map[string]string)
		for k, v := range labels {
			if strVal, ok := v.(string); ok {
				opts.Labels[k] = strVal
			}
		}
	}

	if detach, ok := args["detach"].(bool); ok {
		opts.Detach = detach
	}

	if remove, ok := args["remove"].(bool); ok {
		opts.Remove = remove
	}

	if interactive, ok := args["interactive"].(bool); ok {
		opts.Interactive = interactive
	}

	if tty, ok := args["tty"].(bool); ok {
		opts.TTY = tty
	}

	if privileged, ok := args["privileged"].(bool); ok {
		opts.Privileged = privileged
	}

	if readOnly, ok := args["readOnly"].(bool); ok {
		opts.ReadOnly = readOnly
	}

	if restartPolicy, ok := args["restartPolicy"].(string); ok && restartPolicy != "" {
		opts.RestartPolicy = restartPolicy
	}

	// Execute run
	result, err := runtime.RunContainer(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to run container: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Run Report (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=========================\n"))
	output.WriteString(fmt.Sprintf("Image: %s\n", image))
	if result.Name != "" {
		output.WriteString(fmt.Sprintf("Container Name: %s\n", result.Name))
	}
	if result.ContainerID != "" {
		output.WriteString(fmt.Sprintf("Container ID: %s\n", result.ContainerID))
	}
	output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	output.WriteString(fmt.Sprintf("Exit Code: %d\n", result.ExitCode))
	output.WriteString("\n")

	if result.Output != "" {
		output.WriteString("Container Output:\n")
		output.WriteString("-----------------\n")
		output.WriteString(result.Output)
		output.WriteString("\n")
	}

	if result.Success {
		if opts.Detach {
			output.WriteString(fmt.Sprintf("✅ Container started successfully in detached mode!\n"))
		} else {
			output.WriteString(fmt.Sprintf("✅ Container ran successfully!\n"))
		}
	} else {
		output.WriteString(fmt.Sprintf("❌ Container run failed: %v\n", result.Error))
	}

	return NewTextResult(output.String(), result.Error), nil
}

// Continue with the remaining container management functions...
// (containerList, containerInspect, containerStop, containerRemove, containerLogs, containerExec, containerRuntimeInfo, containerRuntimeVersion)

// containerList lists containers
func (s *Server) containerList(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// List options
	opts := container.ListContainersOptions{}

	if all, ok := args["all"].(bool); ok {
		opts.All = all
	}

	if filter, ok := args["filter"].(string); ok && filter != "" {
		opts.Filter = filter
	}

	if quiet, ok := args["quiet"].(bool); ok {
		opts.Quiet = quiet
	}

	if size, ok := args["size"].(bool); ok {
		opts.Size = size
	}

	// Execute list
	containers, err := runtime.ListContainers(ctx, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list containers: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Containers (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=================\n"))
	output.WriteString(fmt.Sprintf("Found %d containers\n\n", len(containers)))

	if opts.Quiet {
		for _, container := range containers {
			output.WriteString(fmt.Sprintf("%s\n", container.ID))
		}
	} else {
		if opts.Size {
			output.WriteString(fmt.Sprintf("%-12s %-20s %-30s %-15s %-15s %-10s %s\n", "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "SIZE", "NAMES"))
		} else {
			output.WriteString(fmt.Sprintf("%-12s %-20s %-30s %-15s %-15s %s\n", "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"))
		}
		output.WriteString(strings.Repeat("-", 120) + "\n")

		for _, container := range containers {
			containerID := container.ID
			if len(containerID) > 12 {
				containerID = containerID[:12]
			}

			image := container.Image
			if len(image) > 20 {
				image = image[:17] + "..."
			}

			command := container.Command
			if len(command) > 30 {
				command = command[:27] + "..."
			}

			created := container.Created.Format("2006-01-02 15:04")
			names := strings.Join(container.Names, ",")

			if opts.Size {
				size := fmt.Sprintf("%.1f MB", float64(container.Size)/(1024*1024))
				output.WriteString(fmt.Sprintf("%-12s %-20s %-30s %-15s %-15s %-10s %s\n",
					containerID, image, command, created, container.Status, size, names))
			} else {
				output.WriteString(fmt.Sprintf("%-12s %-20s %-30s %-15s %-15s %s\n",
					containerID, image, command, created, container.Status, names))
			}
		}
	}

	return NewTextResult(output.String(), nil), nil
}

// containerInspect inspects a container
func (s *Server) containerInspect(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	containerID, ok := args["containerId"].(string)
	if !ok || containerID == "" {
		return NewTextResult("", fmt.Errorf("containerId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Execute inspect
	inspect, err := runtime.InspectContainer(ctx, containerID)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to inspect container: %w", err)), nil
	}

	// Format result as JSON
	jsonData, err := json.MarshalIndent(inspect, "", "  ")
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to marshal inspect data: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Inspect (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("======================\n"))
	output.WriteString(fmt.Sprintf("Container: %s\n\n", containerID))
	output.WriteString(string(jsonData))

	return NewTextResult(output.String(), nil), nil
}

// containerStop stops a container
func (s *Server) containerStop(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	containerID, ok := args["containerId"].(string)
	if !ok || containerID == "" {
		return NewTextResult("", fmt.Errorf("containerId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Stop options
	var timeout *time.Duration
	if timeoutVal, ok := args["timeout"].(float64); ok {
		t := time.Duration(timeoutVal) * time.Second
		timeout = &t
	}

	// Execute stop
	err = runtime.StopContainer(ctx, containerID, timeout)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to stop container: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Stop (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("==================\n"))
	output.WriteString(fmt.Sprintf("✅ Container '%s' stopped successfully!\n", containerID))

	return NewTextResult(output.String(), nil), nil
}

// containerRemove removes a container
func (s *Server) containerRemove(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	containerID, ok := args["containerId"].(string)
	if !ok || containerID == "" {
		return NewTextResult("", fmt.Errorf("containerId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Remove options
	force, _ := args["force"].(bool)

	// Execute remove
	err = runtime.RemoveContainer(ctx, containerID, force)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to remove container: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Removal (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("=====================\n"))
	output.WriteString(fmt.Sprintf("✅ Container '%s' removed successfully!\n", containerID))

	return NewTextResult(output.String(), nil), nil
}

// containerLogs gets container logs
func (s *Server) containerLogs(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	containerID, ok := args["containerId"].(string)
	if !ok || containerID == "" {
		return NewTextResult("", fmt.Errorf("containerId is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Logs options
	opts := container.LogsOptions{}

	if follow, ok := args["follow"].(bool); ok {
		opts.Follow = follow
	}

	if since, ok := args["since"].(string); ok && since != "" {
		opts.Since = since
	}

	if until, ok := args["until"].(string); ok && until != "" {
		opts.Until = until
	}

	if timestamps, ok := args["timestamps"].(bool); ok {
		opts.Timestamps = timestamps
	}

	if tail, ok := args["tail"].(string); ok && tail != "" {
		opts.Tail = tail
	}

	// Execute logs
	logReader, err := runtime.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get container logs: %w", err)), nil
	}
	defer logReader.Close()

	// Read logs
	logData := make([]byte, 64*1024) // 64KB buffer
	n, readErr := logReader.Read(logData)

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Logs (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("==================\n"))
	output.WriteString(fmt.Sprintf("Container: %s\n\n", containerID))

	if n > 0 {
		output.WriteString("Logs:\n")
		output.WriteString("-----\n")
		output.WriteString(string(logData[:n]))

		if readErr != nil && readErr.Error() != "EOF" {
			output.WriteString(fmt.Sprintf("\n⚠️  Warning: Log reading incomplete: %v\n", readErr))
		}
	} else {
		output.WriteString("No logs available.\n")
	}

	return NewTextResult(output.String(), nil), nil
}

// containerExec executes a command in a container
func (s *Server) containerExec(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	// Validate required arguments
	containerID, ok := args["containerId"].(string)
	if !ok || containerID == "" {
		return NewTextResult("", fmt.Errorf("containerId is required")), nil
	}

	command, ok := args["command"].([]interface{})
	if !ok || len(command) == 0 {
		return NewTextResult("", fmt.Errorf("command is required")), nil
	}

	// Get runtime
	runtimeName, _ := args["runtime"].(string)
	runtime, err := s.getRuntime(runtimeName)
	if err != nil {
		return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
	}

	// Exec options
	opts := container.ExecOptions{}

	// Convert command
	opts.Command = make([]string, len(command))
	for i, v := range command {
		if strVal, ok := v.(string); ok {
			opts.Command[i] = strVal
		}
	}

	if user, ok := args["user"].(string); ok && user != "" {
		opts.User = user
	}

	if workingDir, ok := args["workingDir"].(string); ok && workingDir != "" {
		opts.WorkingDir = workingDir
	}

	if env, ok := args["env"].([]interface{}); ok {
		opts.Env = make([]string, len(env))
		for i, v := range env {
			if strVal, ok := v.(string); ok {
				opts.Env[i] = strVal
			}
		}
	}

	if privileged, ok := args["privileged"].(bool); ok {
		opts.Privileged = privileged
	}

	if interactive, ok := args["interactive"].(bool); ok {
		opts.Interactive = interactive
	}

	if tty, ok := args["tty"].(bool); ok {
		opts.TTY = tty
	}

	// Execute command
	result, err := runtime.ExecContainer(ctx, containerID, opts)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to execute command: %w", err)), nil
	}

	// Format result
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Container Exec (%s)\n", runtime.Name()))
	output.WriteString(fmt.Sprintf("==================\n"))
	output.WriteString(fmt.Sprintf("Container: %s\n", containerID))
	output.WriteString(fmt.Sprintf("Command: %s\n", strings.Join(opts.Command, " ")))
	output.WriteString(fmt.Sprintf("Exit Code: %d\n\n", result.ExitCode))

	if result.Output != "" {
		output.WriteString("Output:\n")
		output.WriteString("-------\n")
		output.WriteString(result.Output)
		output.WriteString("\n")
	}

	if result.Error != "" {
		output.WriteString("Error:\n")
		output.WriteString("------\n")
		output.WriteString(result.Error)
		output.WriteString("\n")
	}

	if result.ExitCode == 0 {
		output.WriteString("✅ Command executed successfully!\n")
	} else {
		output.WriteString(fmt.Sprintf("❌ Command failed with exit code %d\n", result.ExitCode))
	}

	return NewTextResult(output.String(), nil), nil
}

// containerRuntimeInfo gets runtime information
func (s *Server) containerRuntimeInfo(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	manager := s.getContainerManager()

	// Check if specific runtime is requested
	if runtimeName, ok := args["runtime"].(string); ok && runtimeName != "" {
		runtime, err := manager.GetRuntime(runtimeName)
		if err != nil {
			return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
		}

		info, err := runtime.Info(ctx)
		if err != nil {
			return NewTextResult("", fmt.Errorf("failed to get runtime info: %w", err)), nil
		}

		// Format result as JSON
		jsonData, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return NewTextResult("", fmt.Errorf("failed to marshal info data: %w", err)), nil
		}

		var output strings.Builder
		output.WriteString(fmt.Sprintf("Container Runtime Info (%s)\n", runtimeName))
		output.WriteString(fmt.Sprintf("============================\n"))
		output.WriteString(string(jsonData))

		return NewTextResult(output.String(), nil), nil
	}

	// Get info for all available runtimes
	runtimeInfo, err := manager.GetRuntimeInfo(ctx)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get runtime info: %w", err)), nil
	}

	// Format result as JSON
	jsonData, err := json.MarshalIndent(runtimeInfo, "", "  ")
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to marshal info data: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString("Container Runtime Info\n")
	output.WriteString("======================\n")
	output.WriteString(fmt.Sprintf("Available runtimes: %s\n\n", strings.Join(manager.GetAvailableRuntimes(), ", ")))
	output.WriteString(string(jsonData))

	return NewTextResult(output.String(), nil), nil
}

// containerRuntimeVersion gets runtime version information
func (s *Server) containerRuntimeVersion(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	manager := s.getContainerManager()

	// Check if specific runtime is requested
	if runtimeName, ok := args["runtime"].(string); ok && runtimeName != "" {
		runtime, err := manager.GetRuntime(runtimeName)
		if err != nil {
			return NewTextResult("", fmt.Errorf("container runtime not available: %w", err)), nil
		}

		version, err := runtime.Version(ctx)
		if err != nil {
			return NewTextResult("", fmt.Errorf("failed to get runtime version: %w", err)), nil
		}

		// Format result as JSON
		jsonData, err := json.MarshalIndent(version, "", "  ")
		if err != nil {
			return NewTextResult("", fmt.Errorf("failed to marshal version data: %w", err)), nil
		}

		var output strings.Builder
		output.WriteString(fmt.Sprintf("Container Runtime Version (%s)\n", runtimeName))
		output.WriteString(fmt.Sprintf("===============================\n"))
		output.WriteString(string(jsonData))

		return NewTextResult(output.String(), nil), nil
	}

	// Get version for all available runtimes
	runtimeVersions, err := manager.GetRuntimeVersions(ctx)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get runtime versions: %w", err)), nil
	}

	// Format result as JSON
	jsonData, err := json.MarshalIndent(runtimeVersions, "", "  ")
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to marshal version data: %w", err)), nil
	}

	var output strings.Builder
	output.WriteString("Container Runtime Versions\n")
	output.WriteString("===========================\n")
	output.WriteString(fmt.Sprintf("Available runtimes: %s\n\n", strings.Join(manager.GetAvailableRuntimes(), ", ")))
	output.WriteString(string(jsonData))

	return NewTextResult(output.String(), nil), nil
}
