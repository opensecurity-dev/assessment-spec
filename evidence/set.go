package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Artifact is a loaded manifest with its resolved locations.
type Artifact struct {
	Manifest     Manifest
	ManifestPath string
	ArtifactPath string
}

// Set is the evidence loaded from one directory of manifests.
type Set struct {
	Artifacts []Artifact
}

// LoadSet reads and validates every *.manifest.json in dir, resolving each
// artifact path against dir. It does not read artifacts; call VerifyHashes
// for integrity and Freshness for age.
func LoadSet(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("evidence: reading %q: %w", dir, err)
	}
	set := &Set{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ManifestSuffix) {
			continue
		}
		mp := filepath.Join(dir, e.Name())
		m, err := ReadManifest(mp)
		if err != nil {
			return nil, err
		}
		set.Artifacts = append(set.Artifacts, Artifact{
			Manifest:     m,
			ManifestPath: mp,
			ArtifactPath: filepath.Join(dir, filepath.FromSlash(m.ArtifactPath)),
		})
	}
	sort.Slice(set.Artifacts, func(i, j int) bool {
		a, b := set.Artifacts[i], set.Artifacts[j]
		if a.Manifest.Tool != b.Manifest.Tool {
			return a.Manifest.Tool < b.Manifest.Tool
		}
		return a.ManifestPath < b.ManifestPath
	})
	return set, nil
}

// ReadManifest reads and validates one manifest file. Unknown fields are
// rejected so a typo cannot silently drop provenance.
func ReadManifest(path string) (Manifest, error) {
	f, err := os.Open(path) //nolint:gosec // reading the caller's evidence directory is the purpose
	if err != nil {
		return Manifest{}, fmt.Errorf("evidence: opening %q: %w", path, err)
	}
	defer closeOrPanic(f)
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("evidence: parsing %q: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("evidence: %q: %w", path, err)
	}
	return m, nil
}

// VerifyHashes checks the SHA-256 of every artifact that declares one and
// returns one error per mismatch or unreadable artifact.
func (s *Set) VerifyHashes() []error {
	var errs []error
	for _, a := range s.Artifacts {
		if a.Manifest.SHA256 == "" {
			continue
		}
		sum, err := HashFile(a.ArtifactPath)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if sum != a.Manifest.SHA256 {
			errs = append(errs, fmt.Errorf("evidence: tool %q artifact %q sha256 mismatch: manifest %s, actual %s",
				a.Manifest.Tool, a.ArtifactPath, a.Manifest.SHA256, sum))
		}
	}
	return errs
}

// Tools returns the sorted, unique tool names in the set.
func (s *Set) Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range s.Artifacts {
		if !seen[a.Manifest.Tool] {
			seen[a.Manifest.Tool] = true
			out = append(out, a.Manifest.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// HashFile returns the lowercase hex SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // hashing the caller's artifact is the purpose
	if err != nil {
		return "", fmt.Errorf("evidence: opening artifact %q: %w", path, err)
	}
	defer closeOrPanic(f)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("evidence: reading artifact %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// closeOrPanic closes a file opened read-only. Close on a read-only file
// reports only programming errors such as a double close, so it panics.
func closeOrPanic(f *os.File) {
	if err := f.Close(); err != nil {
		panic(fmt.Sprintf("evidence: closing %q: %v", f.Name(), err))
	}
}
