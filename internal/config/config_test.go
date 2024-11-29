package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	config, err := Load("testdata/config.yaml")
	require.NoError(t, err)
	require.Len(t, config.Rules, 1)
	require.Len(t, config.Rules[0].AllOf, 3)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "Valid Config",
			config: Config{
				Rules: []Rule{
					{Match: "some-match"},
				},
			},
			wantErr: false,
		},
		{
			name: "Config with invalid rule",
			config: Config{
				Rules: []Rule{
					{Match: "some-match", AllOf: []Rule{{Match: "sub-match"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "Config with more than one rule",
			config: Config{
				Rules: []Rule{
					{Match: "some-match"},
					{AllOf: []Rule{{Match: "sub-match"}}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(&tt.config); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name:    "Valid Match Rule",
			rule:    Rule{Match: "some-match"},
			wantErr: false,
		},
		{
			name:    "Valid AllOf Rule",
			rule:    Rule{AllOf: []Rule{{Match: "sub-match"}}},
			wantErr: false,
		},
		{
			name:    "Valid AnyOf Rule",
			rule:    Rule{AnyOf: []Rule{{Match: "sub-match"}, {AnyOf: []Rule{{Match: "sub-sub-match"}, {Match: "sub-sub-match"}}}}},
			wantErr: false,
		},
		{
			name:    "Valid Not Rule",
			rule:    Rule{Not: &Rule{Match: "sub-match"}},
			wantErr: false,
		},
		{
			name:    "Valid OneOf Rule",
			rule:    Rule{OneOf: []Rule{{Match: "first-match"}, {Match: "second-match"}}},
			wantErr: false,
		},
		{
			name:    "Multiple conditions",
			rule:    Rule{Match: "some-match", AllOf: []Rule{{Match: "sub-match"}}},
			wantErr: true,
		},
		{
			name:    "No Conditions",
			rule:    Rule{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRule(&tt.rule); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
