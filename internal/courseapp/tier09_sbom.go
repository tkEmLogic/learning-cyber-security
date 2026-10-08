package courseapp

// Tier 9's firmware SBOM and build manifest (#277).
//
// No tool writes a usable SBOM for this firmware. west spdx writes SPDX 2.3,
// which BSI TR-03183-2 does not accept, and it names only Zephyr, Mbed TLS and
// TF-PSA-Crypto: MCUboot and the Espressif HAL get a commit hash, and the
// Wi-Fi libraries and TinyCrypt do not appear at all (#266). So the course
// writes its own, in CycloneDX 1.6 JSON, from facts the build already leaves
// behind:
//
//   - compile_commands.json, for which module's sources were compiled into
//     each image, so a module the build could merely see is not listed;
//   - build.ninja, for which precompiled Espressif libraries were linked;
//   - hal_espressif's zephyr/module.yml, for those libraries' hashes and the
//     commit each was fetched from;
//   - course-build.json, which ./course build firmware writes beside the
//     build, for the source revision, the clean-tree flag and the West patch.
//
// Every C component carries a purl, because grype binds a VEX statement to a
// component only by purl, and a CPE where one exists, because grype matches C
// components only by CPE (#267). Zephyr is a "library", never an
// "operating-system": grype skips that type without a word.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// tier09BuildRecord is what the build knows about itself that nothing after
// it can recover: whether the tree was clean when it built, and whether the
// patch was on the module while it did. It is written by ./course build
// firmware and read by ./course sbom firmware.
type tier09BuildRecord struct {
	SchemaVersion        int                  `json:"schema_version"`
	ReleaseID            string               `json:"release_id"`
	Variant              string               `json:"variant"`
	BuiltAt              string               `json:"built_at"`
	SourceRevision       string               `json:"source_revision"`
	CleanTree            bool                 `json:"clean_tree"`
	Application          string               `json:"application"`
	Board                string               `json:"board"`
	ConfigFragmentSHA256 string               `json:"config_fragment_sha256"`
	Projects             []tier09Project      `json:"projects"`
	WestPatches          []tier09AppliedPatch `json:"west_patches"`
	// HandoverPatch is set only for Tier 10's candidate: the application-level
	// patch applied to the build-time copy of the tree (#290, T10-W-38).
	HandoverPatch *tier10HandoverRecord `json:"handover_patch,omitempty"`
}

// tier10HandoverRecord names the handover patch a build carried, so the build
// record and manifest are honest that the image is the committed tree plus that
// patch, not the committed tree alone (#290).
type tier10HandoverRecord struct {
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	AppliedTo   string `json:"applied_to"`
	Description string `json:"description"`
}

// tier09Project is one West project as the build found it.
type tier09Project struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

// tier09AppliedPatch is one West patch that was on a module while the image
// built. The module's commit does not change when a patch is applied, so this
// is the only record that the compiled source differs from the commit.
type tier09AppliedPatch struct {
	Module string `json:"module"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Fixes  string `json:"fixes"`
}

// tier09Projects are the West projects a Tier 9 image can draw on, with the
// fork each is fetched from. The upstream a component belongs to is in its
// purl; this is where the bytes actually came from.
var tier09Projects = []struct {
	name, path, fork string
}{
	{"zephyr", "zephyr", "https://github.com/zephyrproject-rtos/zephyr"},
	{"mcuboot", "bootloader/mcuboot", "https://github.com/zephyrproject-rtos/mcuboot"},
	{"hal_espressif", "modules/hal/espressif", "https://github.com/zephyrproject-rtos/hal_espressif"},
	{"mbedtls", "modules/crypto/mbedtls", "https://github.com/zephyrproject-rtos/mbedtls"},
	{"tf-psa-crypto", "modules/crypto/tf-psa-crypto", "https://github.com/zephyrproject-rtos/tf-psa-crypto"},
}

// writeTier09BuildRecord records the build. It runs after a successful build,
// so a failed build leaves no record claiming an image exists.
func (a *app) writeTier09BuildRecord(variant firmwareVariant, buildDir, confPath string, clean bool, revision string) error {
	fragment, err := fileSHA256Hex(confPath)
	if err != nil {
		return err
	}
	record := tier09BuildRecord{
		SchemaVersion:        1,
		ReleaseID:            variant.releaseID,
		Variant:              variant.label,
		BuiltAt:              timeNowUTC(),
		SourceRevision:       revision,
		CleanTree:            clean,
		Application:          firmwareApps[tier09],
		Board:                a.manifest.Devices["reference_beacon"].Board,
		ConfigFragmentSHA256: fragment,
	}
	for _, project := range tier09Projects {
		out, err := exec.Command("git", "-C", filepath.Join(a.zephyrWorkspace(), project.path), "rev-parse", "HEAD").Output()
		if err != nil {
			return fmt.Errorf("cannot read the commit of %s: %w", project.path, err)
		}
		record.Projects = append(record.Projects, tier09Project{project.name, project.path, strings.TrimSpace(string(out))})
	}
	if variant.westPatches {
		patch := filepath.Join(a.root, firmwareApps[tier09], "patches", "tf-psa-crypto", "cve-2026-50583.patch")
		sum, err := fileSHA256Hex(patch)
		if err != nil {
			return err
		}
		record.WestPatches = append(record.WestPatches, tier09AppliedPatch{
			Module: tier09PatchedModule,
			File:   filepath.ToSlash(filepath.Join(firmwareApps[tier09], "patches", "tf-psa-crypto", "cve-2026-50583.patch")),
			SHA256: sum,
			Fixes:  "CVE-2026-50583",
		})
	}
	return writeJSON(filepath.Join(buildDir, "course-build.json"), record, 0o644)
}

// treeIsClean asks git whether the working tree has any change at all,
// untracked files included. A build from a dirty tree names a revision nobody
// can check out, and the service refuses to approve one (#271).
func (a *app) treeIsClean() bool {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = a.root
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == ""
}

func (a *app) fullSourceRevision() string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = a.root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// The CycloneDX 1.6 shapes the course writes. Only the fields it fills.
type cdxBOM struct {
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
	Lifecycles []cdxLifecycle `json:"lifecycles,omitempty"`
	Tools      cdxTools       `json:"tools"`
	Authors    []cdxContact   `json:"authors,omitempty"`
	Component  cdxComponent   `json:"component"`
	Properties []cdxProp      `json:"properties,omitempty"`
}

type cdxLifecycle struct {
	Phase string `json:"phase"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxContact struct {
	Name string `json:"name"`
}

type cdxOrg struct {
	Name string   `json:"name"`
	URL  []string `json:"url,omitempty"`
}

type cdxComponent struct {
	Type        string       `json:"type"`
	BOMRef      string       `json:"bom-ref,omitempty"`
	Supplier    *cdxOrg      `json:"supplier,omitempty"`
	Group       string       `json:"group,omitempty"`
	Name        string       `json:"name"`
	Version     string       `json:"version,omitempty"`
	Description string       `json:"description,omitempty"`
	Hashes      []cdxHash    `json:"hashes,omitempty"`
	CPE         string       `json:"cpe,omitempty"`
	PURL        string       `json:"purl,omitempty"`
	Pedigree    *cdxPedigree `json:"pedigree,omitempty"`
	ExternalRef []cdxExtRef  `json:"externalReferences,omitempty"`
	Properties  []cdxProp    `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxPedigree struct {
	Patches []cdxPatch `json:"patches,omitempty"`
	Notes   string     `json:"notes,omitempty"`
}

type cdxPatch struct {
	Type     string        `json:"type"`
	Diff     *cdxDiff      `json:"diff,omitempty"`
	Resolves []cdxResolved `json:"resolves,omitempty"`
}

type cdxDiff struct {
	URL string `json:"url"`
}

type cdxResolved struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	URL  string `json:"url,omitempty"`
}

type cdxExtRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// compiledFiles counts, for each root, the compiled sources under it. A
// module is in an image when this is above zero, and not otherwise:
// zephyr_modules.txt lists every module the build could see, which is how the
// bootloader's west spdx output came to list Mbed TLS it never compiles.
func compiledFiles(compileCommands string, roots map[string]string) (map[string]int, error) {
	data, err := os.ReadFile(compileCommands)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s; build the image first: %w", compileCommands, err)
	}
	var entries []struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%s is not a compilation database: %w", compileCommands, err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		file := filepath.Clean(entry.File)
		for name, root := range roots {
			if strings.HasPrefix(file, filepath.Clean(root)+string(filepath.Separator)) {
				counts[name]++
			}
		}
	}
	return counts, nil
}

// espBlob is one precompiled library as hal_espressif's module.yml records it.
type espBlob struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
	URL    string `yaml:"url"`
}

var githubRawURL = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/raw/([0-9a-f]{40})/(.+)$`)

// linkedBlobs finds the precompiled Espressif libraries the image links, by
// the -l flags in its build.ninja, and returns each with the hash and commit
// module.yml records. A library the build links and module.yml does not know
// is an error, because an SBOM that silently omitted it would be the gap #266
// found, kept.
func linkedBlobs(buildNinja, moduleYML, soc string) ([]espBlob, error) {
	ninja, err := os.ReadFile(buildNinja)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(moduleYML)
	if err != nil {
		return nil, err
	}
	var module struct {
		Blobs []espBlob `yaml:"blobs"`
	}
	if err := yaml.Unmarshal(raw, &module); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", moduleYML, err)
	}
	known := map[string]espBlob{}
	for _, blob := range module.Blobs {
		if dir, file := filepath.Split(blob.Path); dir == "lib/"+soc+"/" {
			known[strings.TrimSuffix(strings.TrimPrefix(file, "lib"), ".a")] = blob
		}
	}
	// The Espressif libraries are linked by name from the blob directory,
	// so only the names module.yml lists for this SoC count; -lgcc and the
	// like are the toolchain's.
	linked := map[string]bool{}
	for _, match := range regexp.MustCompile(`\s-l([a-z0-9_]+)\b`).FindAllStringSubmatch(string(ninja), -1) {
		if _, ok := known[match[1]]; ok {
			linked[match[1]] = true
		}
	}
	if !strings.Contains(string(ninja), "blobs/lib/"+soc) && len(linked) > 0 {
		return nil, errors.New("build.ninja links Espressif libraries from somewhere other than the blob directory")
	}
	var names []string
	for name := range linked {
		names = append(names, name)
	}
	sort.Strings(names)
	var blobs []espBlob
	for _, name := range names {
		blobs = append(blobs, known[name])
	}
	return blobs, nil
}

// blobComponent describes one precompiled library. It has no CPE because no
// vulnerability database names these libraries, and the SBOM says so rather
// than inventing one.
func blobComponent(blob espBlob) cdxComponent {
	name := strings.TrimSuffix(filepath.Base(blob.Path), ".a")
	component := cdxComponent{
		Type:        "library",
		BOMRef:      "blob:" + name,
		Supplier:    &cdxOrg{Name: "Espressif Systems"},
		Name:        name,
		Description: "Precompiled, closed-source Espressif library linked into the image",
		Hashes:      []cdxHash{{"SHA-256", blob.SHA256}},
		Properties: []cdxProp{
			{"course:identity-gap", "closed source; no CPE exists for it, so no scanner can match an advisory to it"},
		},
	}
	if m := githubRawURL.FindStringSubmatch(blob.URL); m != nil {
		component.Version = m[3]
		component.PURL = fmt.Sprintf("pkg:github/%s/%s@%s#%s", m[1], m[2], m[3], m[4])
		component.ExternalRef = []cdxExtRef{{Type: "distribution", URL: blob.URL}}
	}
	return component
}

// versionFromDefine reads a quoted version string from a C header.
func versionFromDefine(header, define string) (string, error) {
	data, err := os.ReadFile(header)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(define) + `\s+"([^"]+)"`).FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("%s does not define %s", header, define)
	}
	return string(m[1]), nil
}

// versionFromZephyrFile reads a Zephyr-style VERSION file.
func versionFromZephyrFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	major, minor, patch := fields["VERSION_MAJOR"], fields["VERSION_MINOR"], fields["PATCHLEVEL"]
	if major == "" || minor == "" || patch == "" {
		return "", fmt.Errorf("%s is not a Zephyr VERSION file", path)
	}
	return major + "." + minor + "." + patch, nil
}

func projectCommit(record tier09BuildRecord, name string) string {
	for _, project := range record.Projects {
		if project.Name == name {
			return project.Commit
		}
	}
	return ""
}

func forkOf(name string) string {
	for _, project := range tier09Projects {
		if project.name == name {
			return project.fork
		}
	}
	return ""
}

// sourceProps records where a component's bytes came from and at which
// commit, which is not always the upstream its purl names.
func sourceProps(record tier09BuildRecord, name string, compiled int) []cdxProp {
	props := []cdxProp{
		{"course:source-repository", forkOf(name)},
		{"course:source-commit", projectCommit(record, name)},
	}
	if compiled > 0 {
		props = append(props, cdxProp{"course:compiled-files", fmt.Sprint(compiled)})
	}
	return props
}

// tier09Components builds the component list for one image from what it
// compiled and linked. Every version is read from the tree the build used,
// not written down here, so moving a pin moves the SBOM with it.
func (a *app) tier09Components(record tier09BuildRecord, compiled map[string]int, blobs []espBlob) ([]cdxComponent, error) {
	ws := a.zephyrWorkspace()
	var components []cdxComponent

	if n := compiled["zephyr"]; n > 0 {
		version, err := versionFromZephyrFile(filepath.Join(ws, "zephyr", "VERSION"))
		if err != nil {
			return nil, err
		}
		components = append(components, cdxComponent{
			Type:       "library",
			BOMRef:     "zephyr",
			Supplier:   &cdxOrg{Name: "Zephyr Project", URL: []string{"https://www.zephyrproject.org"}},
			Name:       "zephyr",
			Version:    version,
			CPE:        "cpe:2.3:o:zephyrproject:zephyr:" + version + ":*:*:*:*:*:*:*",
			PURL:       "pkg:github/zephyrproject-rtos/zephyr@v" + version,
			Properties: sourceProps(record, "zephyr", n),
		})
	}
	if n := compiled["mcuboot"]; n > 0 {
		version, err := versionFromZephyrFile(filepath.Join(ws, "bootloader", "mcuboot", "boot", "zephyr", "VERSION"))
		if err != nil {
			return nil, err
		}
		components = append(components, cdxComponent{
			Type:     "library",
			BOMRef:   "mcuboot",
			Supplier: &cdxOrg{Name: "MCUboot project", URL: []string{"https://www.trustedfirmware.org/projects/mcuboot"}},
			Name:     "mcuboot",
			Version:  version,
			CPE:      "cpe:2.3:a:mcu-tools:mcuboot:" + version + ":*:*:*:*:*:*:*",
			PURL:     "pkg:github/mcu-tools/mcuboot@v" + version,
			Properties: append(sourceProps(record, "mcuboot", n),
				cdxProp{"course:identity-gap", "the vulnerability databases hold no CPE product for MCUboot, so this CPE matches nothing today"}),
		})
	}
	if n := compiled["tinycrypt"]; n > 0 {
		data, err := os.ReadFile(filepath.Join(ws, "bootloader", "mcuboot", "ext", "tinycrypt", "VERSION"))
		if err != nil {
			return nil, err
		}
		version := strings.TrimSpace(string(data))
		components = append(components, cdxComponent{
			Type:        "library",
			BOMRef:      "tinycrypt",
			Supplier:    &cdxOrg{Name: "Intel Corporation"},
			Name:        "tinycrypt",
			Version:     version,
			Description: "Vendored inside MCUboot; verifies every image signature in the shipped bootloader",
			PURL:        "pkg:github/mcu-tools/mcuboot@v" + record.mcubootVersion(ws) + "#ext/tinycrypt",
			Properties: []cdxProp{
				{"course:compiled-files", fmt.Sprint(n)},
				{"course:identity-gap", "no CPE exists for TinyCrypt, and it has no repository of its own to name"},
			},
		})
	}
	if n := compiled["hal_espressif"]; n > 0 {
		commit := projectCommit(record, "hal_espressif")
		components = append(components, cdxComponent{
			Type:     "library",
			BOMRef:   "hal_espressif",
			Supplier: &cdxOrg{Name: "Espressif Systems"},
			Name:     "hal_espressif",
			Version:  commit,
			PURL:     "pkg:github/zephyrproject-rtos/hal_espressif@" + commit,
			Properties: append(sourceProps(record, "hal_espressif", n),
				cdxProp{"course:identity-gap", "a commit is its only version; it is derived from ESP-IDF, but nothing says which ESP-IDF version, so ESP-IDF advisories cannot be matched"}),
		})
	}
	if n := compiled["wpa_supplicant"]; n > 0 {
		sbom, err := readEspressifSBOM(filepath.Join(ws, "modules", "hal", "espressif", "components", "wpa_supplicant", "sbom.yml"))
		if err != nil {
			return nil, err
		}
		commit := projectCommit(record, "hal_espressif")
		components = append(components, cdxComponent{
			Type:        "library",
			BOMRef:      "wpa_supplicant",
			Supplier:    &cdxOrg{Name: "Espressif Systems"},
			Name:        "wpa_supplicant",
			Version:     sbom.Version,
			Description: sbom.Description,
			CPE:         strings.ReplaceAll(sbom.CPE, "{}", sbom.Version),
			PURL:        "pkg:github/zephyrproject-rtos/hal_espressif@" + commit + "#components/wpa_supplicant",
			Properties: []cdxProp{
				{"course:compiled-files", fmt.Sprint(n)},
				{"course:vendor-sbom", "hal_espressif components/wpa_supplicant/sbom.yml"},
			},
		})
	}
	if n := compiled["mbedtls"]; n > 0 {
		version, err := versionFromDefine(filepath.Join(ws, "modules", "crypto", "mbedtls", "include", "mbedtls", "build_info.h"), "MBEDTLS_VERSION_STRING")
		if err != nil {
			return nil, err
		}
		components = append(components, cdxComponent{
			Type:     "library",
			BOMRef:   "mbedtls",
			Supplier: &cdxOrg{Name: "Mbed TLS project", URL: []string{"https://www.trustedfirmware.org/projects/mbed-tls"}},
			Name:     "mbedtls",
			Version:  version,
			CPE:      "cpe:2.3:a:arm:mbed_tls:" + version + ":*:*:*:*:*:*:*",
			PURL:     "pkg:github/Mbed-TLS/mbedtls@v" + version,
			// NVD files Mbed TLS under more than one vendor, and grype
			// does not merge them (#267), so the second name rides along.
			Properties: append(sourceProps(record, "mbedtls", n),
				cdxProp{"syft:cpe23", "cpe:2.3:a:trustedfirmware:mbed_tls:" + version + ":*:*:*:*:*:*:*"}),
		})
	}
	if n := compiled["tf-psa-crypto"]; n > 0 {
		version, err := versionFromDefine(filepath.Join(ws, "modules", "crypto", "tf-psa-crypto", "include", "tf-psa-crypto", "build_info.h"), "TF_PSA_CRYPTO_VERSION_STRING")
		if err != nil {
			return nil, err
		}
		component := cdxComponent{
			Type:     "library",
			BOMRef:   "tf-psa-crypto",
			Supplier: &cdxOrg{Name: "Mbed TLS project", URL: []string{"https://www.trustedfirmware.org/projects/mbed-tls"}},
			Name:     "tf-psa-crypto",
			Version:  version,
			CPE:      "cpe:2.3:a:arm:tf-psa-crypto:" + version + ":*:*:*:*:*:*:*",
			PURL:     "pkg:github/Mbed-TLS/TF-PSA-Crypto@v" + version,
			Properties: append(sourceProps(record, "tf-psa-crypto", n),
				cdxProp{"syft:cpe23", "cpe:2.3:a:trustedfirmware:tf-psa-crypto:" + version + ":*:*:*:*:*:*:*"}),
		}
		// The version stays the one the tree says. A backport does not make
		// 1.1.0 into 1.1.1, and an SBOM that claimed it did would be the
		// kind of evidence that is true of nothing. The patch is recorded
		// as pedigree, which is what a VEX "fixed" statement points at.
		for _, patch := range record.WestPatches {
			if patch.Module != tier09PatchedModule {
				continue
			}
			component.Pedigree = &cdxPedigree{
				Patches: []cdxPatch{{
					Type: "backport",
					Diff: &cdxDiff{URL: "https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/60"},
					Resolves: []cdxResolved{{
						Type: "security",
						ID:   patch.Fixes,
						URL:  "https://nvd.nist.gov/vuln/detail/" + patch.Fixes,
					}},
				}},
				Notes: fmt.Sprintf("Upstream commit c99519080 applied by west patch during this build only; patch file %s, sha256 %s.", patch.File, patch.SHA256),
			}
		}
		components = append(components, component)
	}
	for _, blob := range blobs {
		components = append(components, blobComponent(blob))
	}
	return components, nil
}

func (r tier09BuildRecord) mcubootVersion(ws string) string {
	version, err := versionFromZephyrFile(filepath.Join(ws, "bootloader", "mcuboot", "boot", "zephyr", "VERSION"))
	if err != nil {
		return "unknown"
	}
	return version
}

type espressifSBOM struct {
	Version     string `yaml:"version"`
	CPE         string `yaml:"cpe"`
	Description string `yaml:"description"`
}

func readEspressifSBOM(path string) (espressifSBOM, error) {
	var sbom espressifSBOM
	raw, err := os.ReadFile(path)
	if err != nil {
		return sbom, err
	}
	if err := yaml.Unmarshal(raw, &sbom); err != nil {
		return sbom, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return sbom, nil
}

// tier09Roots are the source trees whose compiled files make a component.
// Order does not matter: the prefixes do not overlap, except TinyCrypt and
// wpa_supplicant, which are counted as themselves and also inside the module
// that vendors them, as both are true.
func (a *app) tier09Roots() map[string]string {
	ws := a.zephyrWorkspace()
	return map[string]string{
		"zephyr":         filepath.Join(ws, "zephyr"),
		"mcuboot":        filepath.Join(ws, "bootloader", "mcuboot"),
		"tinycrypt":      filepath.Join(ws, "bootloader", "mcuboot", "ext", "tinycrypt"),
		"hal_espressif":  filepath.Join(ws, "modules", "hal", "espressif"),
		"wpa_supplicant": filepath.Join(ws, "modules", "hal", "espressif", "components", "wpa_supplicant"),
		"mbedtls":        filepath.Join(ws, "modules", "crypto", "mbedtls"),
		"tf-psa-crypto":  filepath.Join(ws, "modules", "crypto", "tf-psa-crypto"),
	}
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileHashes gives SHA-256, which the Release manifest uses, and SHA-512,
// which TR-03183-2 asks for.
func fileHashes(path string) ([]cdxHash, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s256 := sha256.Sum256(data)
	s512 := sha512.Sum512(data)
	return []cdxHash{{"SHA-256", hex.EncodeToString(s256[:])}, {"SHA-512", hex.EncodeToString(s512[:])}}, nil
}

// bomSerial derives the serial number from the thing described, so writing
// the SBOM again for the same image gives the same serial rather than a new
// random one each run.
func bomSerial(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func newBOM(record tier09BuildRecord, top cdxComponent, components []cdxComponent) cdxBOM {
	var refs []string
	for _, c := range components {
		refs = append(refs, c.BOMRef)
	}
	seed := top.Name
	for _, h := range top.Hashes {
		seed += h.Content
	}
	return cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: bomSerial(seed),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: record.BuiltAt,
			Tools: cdxTools{Components: []cdxComponent{{
				Type:    "application",
				Name:    "learning-cyber-security ./course sbom firmware",
				Version: record.SourceRevision,
			}}},
			Authors:   []cdxContact{{Name: "Harbor Devices Ltd (fictional course manufacturer)"}},
			Component: top,
			Properties: []cdxProp{
				{"course:source-revision", record.SourceRevision},
				{"course:clean-tree", fmt.Sprint(record.CleanTree)},
				{"course:completeness", "components are those with sources compiled into this image, and the precompiled libraries it links; it is not a claim that nothing is missing"},
			},
		},
		Components:   components,
		Dependencies: []cdxDependency{{Ref: top.BOMRef, DependsOn: refs}},
	}
}

// tier09BuildManifest is the record that ties a release to what built it.
// The service reads only clean_tree from it, and digests the rest (#276).
type tier09BuildManifest struct {
	SchemaVersion        int                   `json:"schema_version"`
	ReleaseID            string                `json:"release_id"`
	SourceRevision       string                `json:"source_revision"`
	CleanTree            bool                  `json:"clean_tree"`
	BuiltAt              string                `json:"built_at"`
	Application          string                `json:"application"`
	Board                string                `json:"board"`
	SecurityCounter      int                   `json:"security_counter"`
	ConfigFragmentSHA256 string                `json:"config_fragment_sha256"`
	SigningKey           string                `json:"signing_key_fingerprint"`
	Toolchain            map[string]string     `json:"toolchain"`
	Projects             []tier09Project       `json:"projects"`
	WestPatches          []tier09AppliedPatch  `json:"west_patches"`
	HandoverPatch        *tier10HandoverRecord `json:"handover_patch,omitempty"`
	Builds               map[string]any        `json:"builds"`
	Outputs              map[string][]cdxHash  `json:"outputs"`
	SBOMs                map[string]string     `json:"sboms"`
	Limitations          []string              `json:"limitations"`
}

// sbomFirmware writes the release's SBOM, the shipped bootloader's SBOM, and
// the build manifest, in that order, because the manifest records the hashes
// of the other two.
func (a *app) sbomFirmware(args []string) error {
	tier, name := "", ""
	for len(args) > 0 {
		if len(args) < 2 {
			return fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--tier":
			tier = normalizeTier(args[1])
		case "--variant":
			name = args[1]
		default:
			return fmt.Errorf("unknown sbom option %s", args[0])
		}
		args = args[2:]
	}
	// Tier 9 and Tier 10 share this command: both write a CycloneDX SBOM over
	// the same Zephyr workspace, differing only in which application and which
	// variant they describe (#290).
	if tier != tier09 && tier != tier10 {
		return errors.New("./course sbom firmware is Tier 9's and Tier 10's; pass --tier 09 or --tier 10 --variant <release>")
	}
	variant, err := a.firmwareTierVariant(tier, name)
	if err != nil {
		return err
	}
	appBase := filepath.Base(firmwareApps[tier])
	buildDir := filepath.Join(a.zephyrWorkspace(), "build", appBase+"-"+variant.label)
	var record tier09BuildRecord
	if err := readJSON(filepath.Join(buildDir, "course-build.json"), &record); err != nil {
		return fmt.Errorf("no build record for %s; run ./course build firmware --tier %s --variant %s first", variant.label, tier, variant.label)
	}
	signed := filepath.Join(a.releaseDir(), variant.imageName)
	if _, err := os.Stat(signed); err != nil {
		return fmt.Errorf("no signed release to describe; run ./course release sign --tier %s --variant %s first", tier, variant.label)
	}
	appBuild := filepath.Join(buildDir, appBase)
	bootBuild := buildDir + "-bootloader"
	soc := "esp32c6"

	// The application image, which is the release.
	appCompiled, err := compiledFiles(filepath.Join(appBuild, "compile_commands.json"), a.tier09Roots())
	if err != nil {
		return err
	}
	blobs, err := linkedBlobs(filepath.Join(appBuild, "build.ninja"),
		filepath.Join(a.zephyrWorkspace(), "modules", "hal", "espressif", "zephyr", "module.yml"), soc)
	if err != nil {
		return err
	}
	appComponents, err := a.tier09Components(record, appCompiled, blobs)
	if err != nil {
		return err
	}
	signedHashes, err := fileHashes(signed)
	if err != nil {
		return err
	}
	top := cdxComponent{
		Type:     "firmware",
		BOMRef:   "release:" + variant.releaseID,
		Supplier: &cdxOrg{Name: "Harbor Devices Ltd (fictional course manufacturer)"},
		Name:     variant.releaseID,
		Version:  variant.version,
		Hashes:   signedHashes,
		PURL:     "pkg:github/tkEmLogic/learning-cyber-security@" + record.SourceRevision + "#" + record.Application,
		Properties: []cdxProp{
			{"course:security-counter", fmt.Sprint(variant.securityCounter)},
			{"course:board", record.Board},
			{"course:image", "the signed application image the release publishes"},
		},
	}
	appBOM := newBOM(record, top, appComponents)

	// The bootloader that ships, which is the separate build, not the one
	// sysbuild makes and the course discards.
	bootCompiled, err := compiledFiles(filepath.Join(bootBuild, "compile_commands.json"), a.tier09Roots())
	if err != nil {
		return err
	}
	bootComponents, err := a.tier09Components(record, bootCompiled, nil)
	if err != nil {
		return err
	}
	bootBin := filepath.Join(bootBuild, "zephyr", "zephyr.bin")
	bootHashes, err := fileHashes(bootBin)
	if err != nil {
		return err
	}
	bootBOM := newBOM(record, cdxComponent{
		Type:     "firmware",
		BOMRef:   "bootloader:" + variant.releaseID,
		Supplier: &cdxOrg{Name: "Harbor Devices Ltd (fictional course manufacturer)"},
		Name:     "mcuboot-bootloader",
		Version:  record.mcubootVersion(a.zephyrWorkspace()),
		Hashes:   bootHashes,
		Properties: []cdxProp{
			{"course:image", "the separately built bootloader flashed at the bootloader offset; not updated over the air"},
		},
	}, bootComponents)

	appPath := filepath.Join(a.releaseDir(), variant.releaseID+".firmware.cdx.json")
	bootPath := filepath.Join(a.releaseDir(), variant.releaseID+".bootloader.cdx.json")
	if err := writeJSON(appPath, appBOM, 0o644); err != nil {
		return err
	}
	if err := writeJSON(bootPath, bootBOM, 0o644); err != nil {
		return err
	}

	manifest, err := a.tier09Manifest(variant, record, appBuild, bootBuild, signed, map[string]string{
		"firmware":   appPath,
		"bootloader": bootPath,
	})
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(a.releaseDir(), variant.releaseID+".build-manifest.json")
	if err := writeJSON(manifestPath, manifest, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: described %s\n", variant.releaseID)
	fmt.Fprintf(a.out, "  release SBOM:    %s (%d components)\n", a.relative(appPath), len(appComponents))
	fmt.Fprintf(a.out, "  bootloader SBOM: %s (%d components)\n", a.relative(bootPath), len(bootComponents))
	fmt.Fprintf(a.out, "  build manifest:  %s\n", a.relative(manifestPath))
	for _, c := range appComponents {
		gap := ""
		for _, p := range c.Properties {
			if p.Name == "course:identity-gap" {
				gap = "  (no scanner can match it)"
			}
		}
		if c.CPE == "" && gap == "" {
			gap = "  (no CPE)"
		}
		fmt.Fprintf(a.out, "    %-16s %-42s%s\n", c.Name, c.Version, gap)
	}
	if !record.CleanTree {
		fmt.Fprintln(a.out, "Note: this image was built from a tree with uncommitted changes. The build")
		fmt.Fprintln(a.out, "Note: manifest says so, and the service will refuse to approve the release.")
	}
	if record.HandoverPatch != nil {
		fmt.Fprintf(a.out, "Note: this image carries the handover patch %s\n", record.HandoverPatch.File)
		fmt.Fprintf(a.out, "Note: sha256 %s, applied to %s.\n", record.HandoverPatch.SHA256, record.HandoverPatch.AppliedTo)
		fmt.Fprintln(a.out, "Note: the build manifest records it, so the record is honest about what built the image.")
	}
	return nil
}

func (a *app) tier09Manifest(variant firmwareVariant, record tier09BuildRecord, appBuild, bootBuild, signed string, sboms map[string]string) (tier09BuildManifest, error) {
	fingerprint, err := a.keyFingerprint(a.publicKeyPath())
	if err != nil {
		return tier09BuildManifest{}, err
	}
	outputs := map[string][]cdxHash{}
	for label, path := range map[string]string{
		"application_elf":      filepath.Join(appBuild, "zephyr", "zephyr.elf"),
		"application_unsigned": filepath.Join(appBuild, "zephyr", "zephyr.bin"),
		"application_signed":   signed,
		"bootloader_shipped":   filepath.Join(bootBuild, "zephyr", "zephyr.bin"),
	} {
		hashes, err := fileHashes(path)
		if err != nil {
			return tier09BuildManifest{}, err
		}
		outputs[label] = hashes
	}
	sbomHashes := map[string]string{}
	for label, path := range sboms {
		sum, err := fileSHA256Hex(path)
		if err != nil {
			return tier09BuildManifest{}, err
		}
		sbomHashes[label] = filepath.Base(path) + " sha256:" + sum
	}
	return tier09BuildManifest{
		SchemaVersion:        1,
		ReleaseID:            variant.releaseID,
		SourceRevision:       record.SourceRevision,
		CleanTree:            record.CleanTree,
		BuiltAt:              record.BuiltAt,
		Application:          record.Application,
		Board:                record.Board,
		SecurityCounter:      variant.securityCounter,
		ConfigFragmentSHA256: record.ConfigFragmentSHA256,
		SigningKey:           fingerprint,
		Toolchain:            a.tier09Toolchain(appBuild),
		Projects:             record.Projects,
		WestPatches:          record.WestPatches,
		HandoverPatch:        record.HandoverPatch,
		Builds: map[string]any{
			"application": map[string]string{"directory": appBuild, "kind": "sysbuild application image"},
			"bootloader_shipped": map[string]string{"directory": bootBuild,
				"kind": "standalone MCUboot build against the Learner's public key; this is the bootloader that is flashed"},
			"bootloader_discarded": map[string]string{"directory": filepath.Join(filepath.Dir(appBuild), "mcuboot"),
				"kind": "the bootloader sysbuild also makes; never flashed, so no SBOM describes it"},
		},
		Outputs: outputs,
		SBOMs:   sbomHashes,
		Limitations: []string{
			"Reproducible builds are not claimed: nothing was rebuilt and compared.",
			"The configuration fragment holds the course Wi-Fi network, so only its hash is recorded.",
		},
	}, nil
}

// tier09Toolchain reads the compiler the build used from its CMake cache.
func (a *app) tier09Toolchain(appBuild string) map[string]string {
	toolchain := map[string]string{}
	data, err := os.ReadFile(filepath.Join(appBuild, "CMakeCache.txt"))
	if err != nil {
		return toolchain
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, key := range []string{"CMAKE_C_COMPILER:", "ZEPHYR_SDK_INSTALL_DIR:", "CMAKE_C_COMPILER_VERSION:"} {
			if strings.HasPrefix(line, key) {
				if _, value, ok := strings.Cut(line, "="); ok {
					toolchain[strings.TrimSuffix(strings.Split(key, ":")[0], ":")] = value
				}
			}
		}
	}
	return toolchain
}
