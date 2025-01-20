package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Bonial-International-GmbH/sops-check/internal/config"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	t.Run("allow unmatched", func(t *testing.T) {
		cfg := &config.Config{AllowUnmatched: true}

		output, err := runWithConfig(t, cfg)
		require.NoError(t, err)
		assert.Contains(t, output, "No issues found.")
	})

	t.Run("SARIF - allow unmatched", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{AllowUnmatched: true}

		_, err := runWithConfig(t, cfg, tmpDir+"/no_issues.sarif")
		require.NoError(t, err)

		createdSarif, err := os.ReadFile(tmpDir + "/no_issues.sarif")
		require.NoError(t, err)

		validSarif, err := os.ReadFile("internal/sops/testdata/sarif_test_outputs/no_issues.sarif")
		require.NoError(t, err)
		assert.Equal(t, createdSarif, validSarif)
	})

	t.Run("everything unmatched", func(t *testing.T) {
		cfg := &config.Config{AllowUnmatched: false}

		output, err := runWithConfig(t, cfg)
		require.Error(t, err)
		assert.Contains(t, output, "Found issues in")
		assert.Contains(t, output, "Unmatched trust anchors:")
	})

	t.Run("SARIF - everything unmatched", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{AllowUnmatched: false}

		_, err := runWithConfig(t, cfg, tmpDir+"/everything_unmatched.sarif")
		require.Error(t, err)

		createdSarif, err := os.ReadFile(tmpDir + "/everything_unmatched.sarif")
		require.NoError(t, err)

		validSarif, err := os.ReadFile("internal/sops/testdata/sarif_test_outputs/everything_unmatched.sarif")
		require.NoError(t, err)
		assert.Equal(t, createdSarif, validSarif)
	})

	t.Run("trust anchors not found", func(t *testing.T) {
		cfg := &config.Config{
			AllowUnmatched: false,
			Rules: []config.Rule{
				{AnyOf: []config.Rule{
					{
						Match: "this-is-trust-anchor-a",
					},
					{
						Match: "this-is-trust-anchor-b",
					},
				},
				},
			},
		}

		output, err := runWithConfig(t, cfg)
		require.Error(t, err)
		assert.Contains(t, output, "Expected trust anchor \"this-is-trust-anchor-a\" was not found.")
		assert.Contains(t, output, "Expected trust anchor \"this-is-trust-anchor-b\" was not found.")
	})

	t.Run("SARIF - trust anchors not found", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfg := &config.Config{
			AllowUnmatched: false,
			Rules: []config.Rule{
				{AnyOf: []config.Rule{
					{
						Match: "this-is-trust-anchor-a",
					},
					{
						Match: "this-is-trust-anchor-b",
					},
				},
				},
			},
		}

		_, err := runWithConfig(t, cfg, tmpDir+"/anchors_not_found.sarif")
		require.Error(t, err)

		createdSarif, err := os.ReadFile(tmpDir + "/anchors_not_found.sarif")
		require.NoError(t, err)

		validSarif, err := os.ReadFile("internal/sops/testdata/sarif_test_outputs/anchors_not_found.sarif")
		require.NoError(t, err)
		assert.Equal(t, createdSarif, validSarif)
	})

	t.Run("bad config file", func(t *testing.T) {
		cfg := &config.Config{
			AllowUnmatched: false,
			Rules: []config.Rule{
				{
					// A valid rule cannot have multiple conditions.
					Match:      "this-is-trust-anchor-a",
					MatchRegex: "^this-is-trust-anchor-[ab]$",
				},
			},
		}

		_, err := runWithConfig(t, cfg)
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to load config")
	})

	t.Run("nonexistent config file", func(t *testing.T) {
		_, err := runWithConfig(t, nil)
		require.Error(t, err)
		assert.Regexp(t, "config file \".*\" not found", err.Error())
	})
}

func runWithConfig(t *testing.T, cfg *config.Config, sarifReportPath ...string) (string, error) {
	configPath := fmt.Sprintf("%s/.sops-check.yaml", t.TempDir())

	if cfg != nil {
		data, err := yaml.Marshal(cfg)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(configPath, data, 0o600))
	}

	var sb strings.Builder
	args := []string{"--config", configPath}

	if len(sarifReportPath) > 0 {
		args = append(args, "--sarif-report-path", sarifReportPath[0])
	}
	err := run(&sb, args)

	return sb.String(), err
}
