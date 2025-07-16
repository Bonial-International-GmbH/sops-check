package rules_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bonial-International-GmbH/sops-check/internal/config"
	"github.com/Bonial-International-GmbH/sops-check/internal/rules"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	Description string     `json:"description"`
	Config      string     `json:"config"`
	TestCases   []testCase `json:"testCases"`
}

type testCase struct {
	Description    string   `json:"description"`
	FilePath       string   `json:"filePath"`
	TrustAnchors   []string `json:"trustAnchors"`
	ExpectSuccess  bool     `json:"expectSuccess"`
	ExpectedOutput string   `json:"expectedOutput"`
}

func loadTestConfig(filePath string) (*testConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var test testConfig
	if err := yaml.Unmarshal(bytes, &test); err != nil {
		return nil, err
	}

	return &test, nil
}

// TestUI finds and runs all UI tests defined in the testdata/ui/ directory.
//
// It asserts that:
//
// - The configuration can be loaded and is valid.
// - The configuration rules can be compiled.
// - The rules evaluate to the expected result for different trust anchor inputs.
// - The human readable output is as expected.
func TestUI(t *testing.T) {
	paths, err := filepath.Glob("testdata/ui/*.yaml")
	require.NoError(t, err)

	for _, path := range paths {
		// Load test config.
		testCfg, err := loadTestConfig(path)
		require.NoError(t, err)

		// Load sops-check configuration.
		reader := strings.NewReader(testCfg.Config)
		cfg, err := config.LoadReader(reader)
		require.NoError(t, err)

		// Compile rules.
		rootRule, err := rules.Compile(cfg.Rules)
		require.NoError(t, err)

		// Run test cases.
		for i, testCase := range testCfg.TestCases {
			name := fmt.Sprintf("%s-%d", filepath.Base(path), i)

			t.Run(name, func(t *testing.T) {
				ctx := rules.NewEvalContext(testCase.FilePath, testCase.TrustAnchors)
				result := rootRule.Eval(ctx)

				assert.Equal(t, testCase.ExpectSuccess, result.Success)
				assert.Equal(t, testCase.ExpectedOutput, result.Format())
			})
		}
	}
}
