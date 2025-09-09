package mcp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/containers/kubernetes-mcp-server/pkg/container"
	kubernetes "github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/output"

	"github.com/containers/kubernetes-mcp-server/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	authenticationapiv1 "k8s.io/api/authentication/v1"
	"k8s.io/klog/v2"
)

// NewServer constructs a new MCP Server instance
func NewServer(cfg Configuration) (*Server, error) {
	// Initialize Kubernetes manager
	manager, err := kubernetes.NewManager(cfg.StaticConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes manager: %w", err)
	}

	// Create a Kubernetes client instance from the manager
	k, err := manager.Derived(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &Server{
		configuration:    &cfg,
		enabledTools:     []string{"validateBaseImageUBI"},
		k:                k,                      // Initialize Kubernetes client
		containerManager: container.NewManager(), // Initialize container manager
	}, nil
}

// validateBaseImageUBI tool handler - validates if Dockerfile uses Red Hat UBI base image
func (s *Server) validateBaseImageUBI(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := ctr.GetArguments()

	dockerfilePath := "Dockerfile" // Default value
	if args["dockerfilePath"] != nil {
		dockerfilePath = args["dockerfilePath"].(string)
	}

	// Check if Dockerfile exists
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		return NewTextResult("", fmt.Errorf("dockerfile not found at path: %s", dockerfilePath)), nil
	}

	// Read Dockerfile content
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to read Dockerfile: %w", err)), nil
	}
	dockerfileContent := string(content)

	// Check for Red Hat UBI base images
	lines := strings.Split(dockerfileContent, "\n")

	ubiFound := false
	var baseImages []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "FROM") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				baseImage := parts[1]
				baseImages = append(baseImages, baseImage)

				// Check if it's a Red Hat UBI image
				if strings.Contains(baseImage, "registry.redhat.io/ubi") ||
					strings.Contains(baseImage, "registry.access.redhat.com/ubi") ||
					strings.Contains(baseImage, "ubi8/") || strings.Contains(baseImage, "ubi9/") {
					ubiFound = true
				}
			}
		}
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Dockerfile validation for: %s\n", dockerfilePath))
	result.WriteString(fmt.Sprintf("Base images found: %v\n", baseImages))

	if ubiFound {
		result.WriteString("✅ PASSED: Red Hat Universal Base Image (UBI) detected\n")
		result.WriteString("The Dockerfile uses Red Hat provided universal base images which are recommended for enterprise containers.\n")
	} else {
		result.WriteString("⚠️  WARNING: No Red Hat Universal Base Image (UBI) detected\n")
		result.WriteString("Consider using Red Hat UBI images (registry.redhat.io/ubi8/*, registry.redhat.io/ubi9/*) for:\n")
		result.WriteString("- Enterprise support and security updates\n")
		result.WriteString("- Compliance with Red Hat container standards\n")
		result.WriteString("- Better integration with OpenShift environments\n")
	}

	return NewTextResult(result.String(), nil), nil
}

type ContextKey string

const TokenScopesContextKey = ContextKey("TokenScopesContextKey")

type Configuration struct {
	Profile      Profile
	ListOutput   output.Output
	StaticConfig *config.StaticConfig
}

type Server struct {
	// k is the Kubernetes client manager
	k *kubernetes.Kubernetes
	// containerManager manages container runtimes
	containerManager *container.Manager
	enabledTools     []string
	configuration    *Configuration
}

// ServeStdio implements the STDIO MCP server
func (s *Server) ServeStdio() error {
	// Create the underlying MCP server
	mcpServer := server.NewMCPServer("kubernetes-mcp-server", "1.0.0")
	s.setupMCPServer(mcpServer)

	// Serve STDIO using the server package function
	return server.ServeStdio(mcpServer)
}

// Implements KubernetesApiTokenVerifier
func (s *Server) KubernetesApiVerifyToken(ctx context.Context, token, audience string) (*authenticationapiv1.UserInfo, []string, error) {
	// TODO: Implement actual token verification logic
	return &authenticationapiv1.UserInfo{}, nil, nil
}

// ServeSse returns an http.Handler for SSE endpoint
func (s *Server) ServeSse(baseURL string, httpServer *http.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("SSE not implemented"))
	})
}

// ServeHTTP returns an http.Handler for streaming endpoint
func (s *Server) ServeHTTP(httpServer *http.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// Create the underlying MCP server and handle the request
		mcpServer := server.NewMCPServer("kubernetes-mcp-server", "1.0.0")
		s.setupMCPServer(mcpServer)

		// Use the server's built-in HTTP handler
		streamableServer := server.NewStreamableHTTPServer(mcpServer)
		streamableServer.ServeHTTP(w, r)
	})
}

// setupMCPServer configures the MCP server with all tools
func (s *Server) setupMCPServer(mcpServer *server.MCPServer) {
	// Get the profile to access all tools
	profile := ProfileFromString("full")
	if profile != nil {
		// Add all tools from the profile (this includes all Kubernetes and container tools)
		allTools := profile.GetTools(s)
		mcpServer.AddTools(allTools...)
	}
}

// GetKubernetesAPIServerHost returns the Kubernetes API server host from the configuration.
func (s *Server) GetKubernetesAPIServerHost() string {
	if s.k == nil {
		return ""
	}
	return s.k.GetAPIServerHost()
}

func (s *Server) GetEnabledTools() []string {
	return s.enabledTools
}

func (s *Server) Close() {
	if s.k != nil {
		s.k.Close()
	}
}

func NewTextResult(content string, err error) *mcp.CallToolResult {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: err.Error(),
				},
			},
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: content,
			},
		},
	}
}

func contextFunc(ctx context.Context, r *http.Request) context.Context {
	// Get the standard Authorization header (OAuth compliant)
	authHeader := r.Header.Get(string(kubernetes.OAuthAuthorizationHeader))
	if authHeader != "" {
		return context.WithValue(ctx, kubernetes.OAuthAuthorizationHeader, authHeader)
	}

	// Fallback to custom header for backward compatibility
	customAuthHeader := r.Header.Get(string(kubernetes.CustomAuthorizationHeader))
	if customAuthHeader != "" {
		return context.WithValue(ctx, kubernetes.OAuthAuthorizationHeader, customAuthHeader)
	}

	return ctx
}

func toolCallLoggingMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		klog.V(5).Infof("mcp tool call: %s(%v)", ctr.Params.Name, ctr.Params.Arguments)
		if ctr.Header != nil {
			buffer := bytes.NewBuffer(make([]byte, 0))
			if err := ctr.Header.WriteSubset(buffer, map[string]bool{"Authorization": true, "authorization": true}); err == nil {
				klog.V(7).Infof("mcp tool call headers: %s", buffer)
			}
		}
		return next(ctx, ctr)
	}
}

func toolScopedAuthorizationMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scopes, ok := ctx.Value(TokenScopesContextKey).([]string)
		if !ok {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but no scope is available", ctr.Params.Name, ctr.Params.Name)), nil
		}
		if !slices.Contains(scopes, "mcp:"+ctr.Params.Name) && !slices.Contains(scopes, ctr.Params.Name) {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but only scopes %s are available", ctr.Params.Name, ctr.Params.Name, scopes)), nil
		}
		return next(ctx, ctr)
	}
}
