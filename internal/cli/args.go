package cli

import "github.com/alecthomas/kingpin/v2"

// Version is the current version of the app, generated at build time.
var Version = "unknown"

// Args are configuration options parsed from CLI args.
type Args struct {
	// CheckPath is the filesystem path to search for SOPS files.
	CheckPath string
	// ConfigPath is the path of the sops-check configuration file.
	ConfigPath string
	// SarifReportPath is the path where the SARIF report should be saved.
	SarifReportPath string
}

// Defaults apply to arguments not provided explicitly.
var Defaults = &Args{
	CheckPath:  ".",
	ConfigPath: ".sops-check.yaml",
}

// ParseArgs parses arguments from the command line.
func ParseArgs(commandLine []string) (*Args, error) {
	args := &Args{}

	app := kingpin.New(
		"sops-check",
		"A tool that looks for SOPS files within a directory tree and ensures they are configured in the desired fashion.",
	)
	app.Version(Version)
	app.DefaultEnvars()

	// Flags.
	app.HelpFlag.Short('h')
	app.Flag("config", "Path to the sops-check configuration file.").
		Short('c').
		Default(Defaults.ConfigPath).
		StringVar(&args.ConfigPath)

	app.Flag("sarif-report-path", "Path where the SARIF report should be created.").
		StringVar(&args.SarifReportPath)

	// Positional arguments.
	app.Arg("path", "Directory to run the checks in. If omitted, checks are run in the current working directory.").
		Default(Defaults.CheckPath).
		StringVar(&args.CheckPath)

	if _, err := app.Parse(commandLine); err != nil {
		return nil, err
	}

	return args, nil
}
