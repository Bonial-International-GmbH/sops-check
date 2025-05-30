package sops

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/ini"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
	ignore "github.com/sabhiram/go-gitignore"
)

func getStore(fileType string) (sops.Store, error) {
	switch fileType {
	case ".ini":
		return &ini.Store{}, nil
	case ".env":
		return &dotenv.Store{}, nil
	case ".yaml", ".yml":
		return &yaml.Store{}, nil
	case ".json":
		return &json.Store{}, nil
	default:
		return nil, fmt.Errorf("unsupported file type: %s", fileType)
	}
}

// File represents a SOPS file and its metadata
type File struct {
	Path     string
	Metadata sops.Metadata
}

// FindFiles searches a directory for YAML files and checks if they are valid SOPS files.
func FindFiles(root string, ignoreObjects []*ignore.GitIgnore) ([]File, error) {
	var sopsFiles []File

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Skip files that are ignored
		for _, ignoreObject := range ignoreObjects {
			if ignoreObject.MatchesPath(path) {
				return nil
			}
		}

		ext := filepath.Ext(d.Name())

		store, err := getStore(ext)
		if err != nil {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("Could not read file:", "filepath", path, "error", err)
			return nil
		}

		tree, err := store.LoadEncryptedFile(data)
		if err != nil {
			return nil
		}

		sopsFiles = append(sopsFiles, File{Path: path, Metadata: tree.Metadata})

		return nil
	})

	return sopsFiles, err
}

// ExctractKeys extracts and returns a list of keys from the given sops.Metadata
func (f *File) ExtractKeys() []string {
	var keys []string
	for _, KeyGroup := range f.Metadata.KeyGroups {
		for _, key := range KeyGroup {
			keys = append(keys, key.ToString())
		}
	}
	return keys
}
