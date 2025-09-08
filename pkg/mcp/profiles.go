package mcp

import (
	"slices"

	"github.com/mark3labs/mcp-go/server"
	"github.com/mark3labs/mcp-go/mcp"
)

type Profile interface {
	GetName() string
	GetDescription() string
	GetTools(s *Server) []server.ServerTool
}

var Profiles = []Profile{
	&FullProfile{},
}

var ProfileNames []string

func ProfileFromString(name string) Profile {
	for _, profile := range Profiles {
		if profile.GetName() == name {
			return profile
		}
	}
	return nil
}

type FullProfile struct{}

func (p *FullProfile) GetName() string {
	return "full"
}
func (p *FullProfile) GetDescription() string {
	return "Complete profile with all tools and extended outputs"
}
func (p *FullProfile) GetTools(s *Server) []server.ServerTool {
	       tools := []server.ServerTool{
		       {Tool: mcp.NewTool("validate_base_image_ubi",
			       mcp.WithDescription("Validate Dockerfile base image is Red Hat UBI. Warn if not."),
			       mcp.WithString("dockerfilePath", mcp.Description("Path to Dockerfile (default: Dockerfile)")),
			       mcp.WithTitleAnnotation("Validate Base Image UBI"),
			       mcp.WithReadOnlyHintAnnotation(true),
			       mcp.WithDestructiveHintAnnotation(false),
		       ), Handler: s.validateBaseImageUBI},
	       }
	       return slices.Concat(
		       s.initConfiguration(),
		       s.initEvents(),
		       s.initNamespaces(),
		       s.initPods(),
		       s.initResources(),
		       s.initHelm(),
		       []server.ServerTool{
			       {Tool: mcp.NewTool("build_container_image",
				       mcp.WithDescription("Build a container image using Podman"),
				       mcp.WithString("imageTag", mcp.Description("Image tag to build (e.g., quay.io/user/image:v1)"), mcp.Required()),
				       mcp.WithTitleAnnotation("Build Container Image"),
				       mcp.WithReadOnlyHintAnnotation(false),
				       mcp.WithDestructiveHintAnnotation(false),
			       ), Handler: s.buildContainerImage},
			       {Tool: mcp.NewTool("push_container_image",
				       mcp.WithDescription("Push a container image using Podman"),
				       mcp.WithString("imageTag", mcp.Description("Image tag to push (e.g., quay.io/user/image:v1)"), mcp.Required()),
				       mcp.WithTitleAnnotation("Push Container Image"),
				       mcp.WithReadOnlyHintAnnotation(false),
				       mcp.WithDestructiveHintAnnotation(false),
			       ), Handler: s.pushContainerImage},
		       },
		       tools,
	       )
}

func init() {
	ProfileNames = make([]string, 0)
	for _, profile := range Profiles {
		ProfileNames = append(ProfileNames, profile.GetName())
	}
}
