// Package main provides the entrypoint for the sops-check executable.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Bonial-International-GmbH/sops-check/internal/cli"
	"github.com/Bonial-International-GmbH/sops-check/internal/config"
	"github.com/Bonial-International-GmbH/sops-check/internal/rules"
	"github.com/Bonial-International-GmbH/sops-check/internal/sops"
	"github.com/Bonial-International-GmbH/sops-check/internal/stringutils"
	"github.com/sabhiram/go-gitignore"
)

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
}

func run(w io.Writer, commandLine []string) error {
	logger := slog.New(slog.NewTextHandler(w, nil))
	slog.SetDefault(logger)
	var ignoreObjects []*ignore.GitIgnore

	args, err := cli.ParseArgs(commandLine)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if len(args.IgnoreFilePath) > 0 {
		for _, ignoreFile := range args.IgnoreFilePath {
			ignoreObject, err := ignore.CompileIgnoreFile(ignoreFile)
			if err != nil {
				return fmt.Errorf("Failed to process ignore file %s : %w", ignoreFile, err)
			}
			ignoreObjects = append(ignoreObjects, ignoreObject)
		}
	}

	cfg, err := config.Load(args.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file %q not found", args.ConfigPath)
		}

		return fmt.Errorf("failed to load config file: %w", err)
	}

	rootRule, err := rules.Compile(cfg.Rules)
	if err != nil {
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	files, err := sops.FindFiles(args.CheckPath, ignoreObjects)
	if err != nil {
		return fmt.Errorf("failed to find sops files: %w", err)
	}

	if err := checkFiles(w, rootRule, cfg, files); err != nil {
		return err
	}

	fmt.Fprintln(w, "✅ No issues found.")

	return nil
}

func checkFiles(w io.Writer, rootRule rules.Rule, cfg *config.Config, files []sops.File) error {
	var problematicFiles []string

	for _, file := range files {
		result := checkFile(w, rootRule, &file)

		// Rules will evaluate to success, even in the presence of excess trust
		// anchors that did not match any rule.
		//
		// The default behaviour is to consider files with unmatched trust
		// anchors as problematic (and thus fail the check), unless
		// `allowUnmatched` is explicitly set to `true` in the configuration.
		if !result.Success || (result.Unmatched.Size() > 0 && !cfg.AllowUnmatched) {
			problematicFiles = append(problematicFiles, file.Path)
		}
	}

	if len(problematicFiles) > 0 {
		var sb strings.Builder

		for _, file := range problematicFiles {
			fmt.Fprintf(&sb, "\n  - %s", file)
		}

		return fmt.Errorf("Found %d files with issues:%s", len(problematicFiles), sb.String())
	}

	return nil
}

func checkFile(w io.Writer, rootRule rules.Rule, file *sops.File) rules.EvalResult {
	ctx := rules.NewEvalContext(file.ExtractKeys())
	result := rootRule.Eval(ctx)
	formattedResult := result.Format()

	if formattedResult != "" {
		fmt.Fprintf(w, "Found issues in %s:\n\n", file.Path)
		fmt.Fprintln(w, stringutils.Indent(formattedResult, 4, true))
	}

	return result
}
