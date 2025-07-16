package rules

import (
	"fmt"
	"regexp"

	"github.com/Bonial-International-GmbH/sops-check/internal/config"
	ignore "github.com/sabhiram/go-gitignore"
)

// Compile takes a slice of rule configurations and compiles it into a single
// rule that can be evaluated.
func Compile(rules []config.Rule) (root Rule, err error) {
	compiled, err := compileRules(rules)
	if err != nil {
		return nil, err
	}

	return AllOf(compiled...), nil
}

func compileRules(rules []config.Rule) ([]Rule, error) {
	compiled := make([]Rule, len(rules))

	for i, rule := range rules {
		compiledRule, err := compileRule(rule)
		if err != nil {
			return nil, err
		}

		compiled[i] = compiledRule
	}

	return compiled, nil
}

func compileRule(config config.Rule) (Rule, error) {
	compiled, err := compileRuleInner(config)
	if err != nil {
		return nil, err
	}

	var pathMatcher *ignore.GitIgnore
	if len(config.Paths) > 0 {
		pathMatcher = ignore.CompileIgnoreLines(config.Paths...)
	}

	compiled.SetMeta(Meta{
		Description: config.Description,
		URL:         config.URL,
		PathMatcher: pathMatcher,
	})

	return compiled, nil
}

func compileRuleInner(rule config.Rule) (Rule, error) {
	if rule.Match != "" {
		return Match(rule.Match), nil
	}

	if rule.MatchRegex != "" {
		pattern, err := regexp.Compile(rule.MatchRegex)
		if err != nil {
			return nil, err
		}

		return MatchRegex(pattern), nil
	}

	if rule.Not != nil {
		inner, err := compileRule(*rule.Not)
		if err != nil {
			return nil, err
		}

		return Not(inner), nil
	}

	if len(rule.AllOf) > 0 {
		rules, err := compileRules(rule.AllOf)
		if err != nil {
			return nil, err
		}

		return AllOf(rules...), nil
	}

	if len(rule.AnyOf) > 0 {
		rules, err := compileRules(rule.AnyOf)
		if err != nil {
			return nil, err
		}

		return AnyOf(rules...), nil
	}

	if len(rule.OneOf) > 0 {
		rules, err := compileRules(rule.OneOf)
		if err != nil {
			return nil, err
		}

		return OneOf(rules...), nil
	}

	return nil, fmt.Errorf("rule %v has no conditions", rule)
}
