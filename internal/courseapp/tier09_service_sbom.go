package courseapp

// `./course sbom service` (#277): a CycloneDX 1.6 JSON SBOM for the OTA
// service, written by the course from the built binary's own build
// information.
//
// It describes the binary, not go.mod. go.mod names test-only modules that are
// in no binary, and it cannot say which standard library was linked in, which
// is the one thing that matters for this service: its whole third-party
// inventory is the Go standard library of the toolchain that built it. So the
// binary is built with the pinned toolchain first, and the SBOM is read out of
// what was built.
//
// It is course-owned rather than made by syft or cyclonedx-gomod, so there is
// no new tool to pin, and so the standard library is spelled the way grype
// matches it. The two tools disagree: syft writes pkg:golang/stdlib@1.24.0,
// cyclonedx-gomod writes pkg:golang/std@go1.24.0 (research/tier-09-sbom.md).

import (
	"crypto/sha256"
	"crypto/sha512"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// The OTA service's main package, and where its binary is built for the SBOM.
// The binary is kept apart from build/ota, which `./course service start`
// rebuilds with whatever Go is on the PATH.
const (
	serviceMainPackage = "./services/ota/cmd/ota"
	serviceSBOMBinary  = "sbom/ota-service"
)

// cycloneDX is the subset of CycloneDX 1.6 this SBOM uses.
type cycloneDX struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

type cdxMetadata struct {
	Timestamp  string         `json:"timestamp"`
	Lifecycles []cdxLifecycle `json:"lifecycles"`
	Tools      cdxTools       `json:"tools"`
	Component  cdxComponent   `json:"component"`
}

type cdxLifecycle struct {
	Phase string `json:"phase"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	BOMRef      string        `json:"bom-ref"`
	Type        string        `json:"type"`
	Group       string        `json:"group,omitempty"`
	Name        string        `json:"name"`
	Version     string        `json:"version,omitempty"`
	Description string        `json:"description,omitempty"`
	PURL        string        `json:"purl,omitempty"`
	CPE         string        `json:"cpe,omitempty"`
	Hashes      []cdxHash     `json:"hashes,omitempty"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// sbomService builds the service with the pinned toolchain and writes its
// SBOM. args are the words after `sbom service`; it takes none.
func (a *app) sbomService(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("sbom service takes no options, got %s", strings.Join(args, " "))
	}
	s, err := a.scanning()
	if err != nil {
		return err
	}
	a.context("OTA service SBOM")

	a.step(1, "Build the service with the toolchain it shipped with")
	binary := filepath.Join(a.root, a.manifest.Paths.Build, serviceSBOMBinary)
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		return err
	}
	// GOTOOLCHAIN, so the SBOM names go1.24.0 on every machine. Without it a
	// host with a newer Go would describe a service that never shipped.
	fmt.Fprintf(a.out, "+ GOTOOLCHAIN=%s go build -o %s %s\n", s.GoToolchain, a.relative(binary), serviceMainPackage)
	if err := runAttachedEnv(a.root, a.out, a.errOut, []string{"GOTOOLCHAIN=" + s.GoToolchain},
		"go", "build", "-o", binary, serviceMainPackage); err != nil {
		return err
	}

	a.step(2, "Read what was linked in, and write the SBOM")
	fmt.Fprintf(a.out, "+ go version -m %s\n", a.relative(binary))
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("cannot read the build information in %s: %w", binary, err)
	}
	if info.GoVersion != s.GoToolchain {
		return fmt.Errorf("the service was built with %s, not the pinned %s", info.GoVersion, s.GoToolchain)
	}
	head, _ := gitOutput(a.root, "rev-parse", "HEAD")
	if err := checkBuildRevision(info, strings.TrimSpace(head)); err != nil {
		return err
	}
	hashes, err := binaryHashes(binary)
	if err != nil {
		return err
	}
	serial, err := randomID()
	if err != nil {
		return err
	}
	bom, err := serviceBOM(info, hashes, a.manifest.Course.Version, "urn:uuid:"+serial, time.Now().UTC())
	if err != nil {
		return err
	}
	path := filepath.Join(a.sbomDir(), serviceSBOMName)
	if err := writeJSON(path, bom, 0o600); err != nil {
		return err
	}
	for _, component := range bom.Components {
		a.note("%s %s  %s", component.Name, component.Version, component.PURL)
	}
	fmt.Fprintf(a.out, "Output: %s\n", a.relative(path))
	fmt.Fprintf(a.out, "Result: SBOM written for the service built with %s; components listed: %d\n", info.GoVersion, len(bom.Components))
	fmt.Fprintln(a.out, "Next: ./course scan service")
	return nil
}

// checkBuildRevision refuses a binary whose recorded source revision is not
// the checkout's HEAD. Go looks for the repository by walking up to the first
// .git directory, and a linked Git worktree has a .git file instead. A
// worktree nested inside another clone is therefore stamped with the outer
// clone's revision, and the SBOM would name source it was not built from.
// A binary with no revision at all, such as one built outside Git, is let
// through: the SBOM then says nothing about its source, which is true.
func checkBuildRevision(info *debug.BuildInfo, head string) error {
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && head != "" && setting.Value != head {
			return fmt.Errorf("the binary records source revision %s, but this checkout is at %s; "+
				"Go does not see a linked Git worktree nested inside another clone, so build from an ordinary clone",
				setting.Value, head)
		}
	}
	return nil
}

// binaryHashes is the SHA-256 and SHA-512 of the built binary, so the SBOM
// can be tied to exactly one file.
func binaryHashes(path string) ([]cdxHash, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	h256, h512 := sha256.New(), sha512.New()
	if _, err := io.Copy(io.MultiWriter(h256, h512), file); err != nil {
		return nil, err
	}
	return []cdxHash{
		{"SHA-256", hexSum(h256)},
		{"SHA-512", hexSum(h512)},
	}, nil
}

func hexSum(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

// serviceBOM turns a binary's build information into the SBOM. It is pure,
// so the shape can be tested without building anything.
func serviceBOM(info *debug.BuildInfo, hashes []cdxHash, courseVersion, serial string, now time.Time) (cycloneDX, error) {
	if info.Main.Path == "" || !strings.HasPrefix(info.GoVersion, "go") {
		return cycloneDX{}, errors.New("the binary carries no module build information")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}

	// The main component: the service binary. Its purl is the module's, with
	// the main package as the purl subpath, because one module builds both
	// the service and the course helper.
	version := info.Main.Version
	if version == "(devel)" {
		version = ""
	}
	subpath := strings.TrimPrefix(strings.TrimPrefix(info.Path, info.Main.Path), "/")
	main := cdxComponent{
		Type:        "application",
		Name:        info.Path,
		Version:     version,
		Description: "The course OTA service, services/ota/cmd/ota",
		PURL:        golangPURL(info.Main.Path, version, subpath),
		Hashes:      hashes,
	}
	main.BOMRef = main.PURL
	for _, key := range []string{"vcs", "vcs.revision", "vcs.time", "vcs.modified", "GOOS", "GOARCH", "CGO_ENABLED"} {
		if value, ok := settings[key]; ok {
			main.Properties = append(main.Properties, cdxProperty{"go:build:" + key, value})
		}
	}
	main.Properties = append(main.Properties, cdxProperty{"go:build:toolchain", info.GoVersion})

	// The standard library, spelled as grype matches it: the version without
	// the "go" prefix, and the golang:go CPE. A version of "go1.24.0" makes
	// osv-scanner match advisories fixed years before Go 1.24.
	goVersion := strings.TrimPrefix(info.GoVersion, "go")
	if i := strings.IndexAny(goVersion, " -"); i >= 0 {
		goVersion = goVersion[:i] // drops suffixes like "-X:nodwarf5"
	}
	stdlib := cdxComponent{
		Type:        "library",
		Name:        "stdlib",
		Version:     goVersion,
		Description: "The Go standard library, linked in by the " + info.GoVersion + " toolchain",
		PURL:        golangPURL("stdlib", goVersion, ""),
		CPE:         fmt.Sprintf("cpe:2.3:a:golang:go:%s:*:*:*:*:*:*:*", goVersion),
	}
	stdlib.BOMRef = stdlib.PURL
	components := []cdxComponent{stdlib}

	// Linked modules. go.sum's h1: value is a hash of the module's source
	// tree in Go's own format, not of any file that ships, so it is kept as a
	// property rather than presented as a CycloneDX hash.
	for _, dep := range info.Deps {
		module := dep
		if dep.Replace != nil {
			module = dep.Replace
		}
		c := cdxComponent{
			Type:    "library",
			Name:    module.Path,
			Version: module.Version,
			PURL:    golangPURL(module.Path, module.Version, ""),
		}
		c.BOMRef = c.PURL
		if module.Sum != "" {
			c.Properties = append(c.Properties, cdxProperty{"go:module:sum", module.Sum})
		}
		if dep.Replace != nil {
			c.Properties = append(c.Properties, cdxProperty{"go:module:replaces", dep.Path + "@" + dep.Version})
		}
		components = append(components, c)
	}

	var refs []string
	for _, c := range components {
		refs = append(refs, c.BOMRef)
	}
	dependencies := []cdxDependency{{Ref: main.BOMRef, DependsOn: refs}}
	for _, c := range components {
		dependencies = append(dependencies, cdxDependency{Ref: c.BOMRef})
	}

	tool := cdxComponent{
		BOMRef:      "course-tool",
		Type:        "application",
		Group:       "github.com/tkEmLogic/learning-cyber-security",
		Name:        "course",
		Version:     courseVersion,
		Description: "./course sbom service, from the binary's Go build information",
	}
	return cycloneDX{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: serial,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp:  now.Format(time.RFC3339),
			Lifecycles: []cdxLifecycle{{"build"}},
			Tools:      cdxTools{Components: []cdxComponent{tool}},
			Component:  main,
		},
		Components:   components,
		Dependencies: dependencies,
	}, nil
}

// golangPURL writes a pkg:golang purl. The module path keeps its case, because
// Go module paths are case-sensitive, and a "+" in a version such as
// "+dirty" is percent-encoded, because the purl specification reserves it.
func golangPURL(path, version, subpath string) string {
	purl := "pkg:golang/" + path
	if version != "" {
		purl += "@" + strings.ReplaceAll(version, "+", "%2B")
	}
	if subpath != "" {
		purl += "#" + subpath
	}
	return purl
}
