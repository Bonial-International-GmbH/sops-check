// Package rules contains the interface for the rule engine and all supported
// rule types together with their rule evaluation logic.
package rules

import ignore "github.com/sabhiram/go-gitignore"

// Meta describes metadata common to all available rules.
type Meta struct {
	// Description may contain the description of the rule. If the description
	// is not empty, it is used to enrich error messages presented to the user.
	Description string
	// URL may contain a link to some (internal) documentation that further
	// explains the purpose of a rule. If non-empty, it is used to enrich error
	// messages presented to the user.
	URL string
	// PathMatcher matches files this rule should apply to. If nil, the rule
	// applies to all files.
	PathMatcher *ignore.GitIgnore
}

// MatchesPath checks if a rule should be applied to the file at path.
func (m Meta) MatchesPath(path string) bool {
	if m.PathMatcher == nil {
		return true
	}

	return m.PathMatcher.MatchesPath(path)
}

// Kind represents the kind of a rule.
type Kind string

const (
	// KindAllOf asserts that all of the nested rules match.
	KindAllOf Kind = "allOf"
	// AnyOf asserts that at least one of the nested rules matches.
	KindAnyOf Kind = "anyOf"
	// Match defines a string to match trust anchors against.
	KindMatch Kind = "match"
	// MatchRegex defines a regular expression to match trust anchors against.
	KindMatchRegex Kind = "matchRegex"
	// Not inverts the matching behaviour of a rule.
	KindNot Kind = "not"
	// OneOf asserts that exactly one of the nested rules matches.
	KindOneOf Kind = "oneOf"
)

// Rule is the interface implemented by all available rules.
type Rule interface {
	// Kind returns the kind of the rule.
	Kind() Kind
	// Meta returns the metadata associated with the rule.
	Meta() Meta
	// SetMeta sets the rule metadata.
	SetMeta(meta Meta)
	// Eval evaluates the rule using the provided EvalContext.
	Eval(ctx *EvalContext) EvalResult
}

// metaRule is used by all available rules as their implementation of
// Rule.Meta() and Rule.SetMeta() to reduce boilerplate.
type metaRule struct {
	meta Meta
}

// Meta returns the metadata associated with the rule.
func (r *metaRule) Meta() Meta {
	return r.meta
}

// SetMeta sets the rule metadata.
func (r *metaRule) SetMeta(meta Meta) {
	r.meta = meta
}

// withMeta sets the rule metadata and returns it.
//
// This function is just a convenience wrapper to all chaining.
func withMeta(rule Rule, meta Meta) Rule {
	rule.SetMeta(meta)
	return rule
}

// Ensure that all rule types implement the Rule interface.
var (
	_ Rule = &AllOfRule{}
	_ Rule = &AnyOfRule{}
	_ Rule = &MatchRule{}
	_ Rule = &MatchRegexRule{}
	_ Rule = &NotRule{}
	_ Rule = &OneOfRule{}
)
