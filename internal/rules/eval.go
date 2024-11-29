package rules

import "github.com/hashicorp/go-set/v3"

// EvalContext encapsulates data needed during rule evaluation, like the trust
// anchors found within a given SOPS file.
type EvalContext struct {
	// FilePath is the relative path to the SOPS file.
	FilePath string
	// TrustAnchors is a set of trust anchors found in a SOPS file.
	TrustAnchors set.Collection[string]
}

// NewEvalContext creates a new EvalContext from a file path and a list of
// trust anchors.
func NewEvalContext(filePath string, trustAnchors []string) *EvalContext {
	return &EvalContext{
		FilePath:     filePath,
		TrustAnchors: set.From(trustAnchors),
	}
}

// filterRules takes a list of rules and only returns the rules that match the
// file path in the EvalContext.
func (c *EvalContext) filterRules(rules []Rule) []Rule {
	filtered := make([]Rule, 0, len(rules))

	for _, rule := range rules {
		meta := rule.Meta()

		if !meta.MatchesPath(c.FilePath) {
			// We don't need to look into potentially nested rules here since
			// we're discarding the rule as a whole.
			continue
		}

		// Rules containing nested rules themselves need to be filtered recursively.
		switch r := rule.(type) {
		case *AllOfRule:
			if nested := c.filterRules(r.rules); len(nested) > 0 {
				filtered = append(filtered, withMeta(AllOf(nested...), meta))
			}
		case *AnyOfRule:
			if nested := c.filterRules(r.rules); len(nested) > 0 {
				filtered = append(filtered, withMeta(AnyOf(nested...), meta))
			}
		case *OneOfRule:
			if nested := c.filterRules(r.rules); len(nested) > 0 {
				filtered = append(filtered, withMeta(OneOf(nested...), meta))
			}
		case *NotRule:
			if nested := c.filterRules([]Rule{r.rule}); len(nested) == 1 {
				filtered = append(filtered, withMeta(Not(nested[0]), meta))
			}
		default:
			filtered = append(filtered, rule)
		}
	}

	return filtered
}

// EvalResult represents the result of a rule evaluation.
type EvalResult struct {
	// Rule is the rule that produced this result.
	Rule Rule
	// Success indicates whether the rule was matched by the input or not.
	Success bool
	// Matched contains trust anchors that were matched during rule evaluation,
	// if any. This may even contain trust anchors if rule evaluation failed,
	// indicating partial matches.
	Matched set.Collection[string]
	// Unmatched contains all trust anchors not matched during rule evaluation.
	Unmatched set.Collection[string]
	// Nested contains the results of any nested rules that had to be evaluated
	// in order to produce the result. This allows identifying the exact nested
	// rules that led to evaluation success (or failure).
	Nested []EvalResult
}

// SarifResult converts the evaluation results to SARIF format.
func (r *EvalResult) SarifResult(filepath string, allowUnmatched bool) SarifResult {
	success := r.Success
	if r.Success && r.Unmatched.Size() > 0 && !allowUnmatched {
		success = false
	}
	sarifResult := SarifResult{
		RuleID:      string(r.Rule.Kind()),
		Evaluation:  map[bool]string{true: "none", false: "error"}[success],
		Kind:        map[bool]string{true: "pass", false: "fail"}[success],
		Message:     r.Format(),
		Description: r.Rule.Meta().Description,
		File:        filepath,
	}
	return sarifResult
}

// partitionNested partitions nested results into success and failure.
func (r *EvalResult) partitionNested() (successes, failures []EvalResult) {
	for _, result := range r.Nested {
		if result.Success {
			successes = append(successes, result)
		} else {
			failures = append(failures, result)
		}
	}

	return
}

// flatten flattens results of compound rules (allOf, anyOf, oneOf) into
// their first nested result if there's only one. This avoids unnecessary
// nesting in the human readable output to make it less verbose.
func (r *EvalResult) flatten() *EvalResult {
	switch r.Rule.(type) {
	case *AllOfRule, *AnyOfRule, *OneOfRule:
		if len(r.Nested) == 1 {
			return &r.Nested[0]
		}
	}

	return r
}

// Format formats the EvalResult as a human readable string.
func (r *EvalResult) Format() string {
	result := r.flatten()

	var buf formatBuffer

	if !result.Success {
		formatFailure(&buf, result)
	}

	if !result.Unmatched.Empty() {
		if !result.Success {
			// Leave some space between the failure output and the unmatched
			// trust anchors.
			buf.WriteRune('\n')
		}

		buf.WriteString("Unmatched trust anchors:\n")
		formatTrustAnchors(&buf, result.Unmatched)
	}

	return buf.String()
}

// evalRulesResult is a helper type returned by evalRules.
type evalRulesResult struct {
	results      []EvalResult
	matched      set.Collection[string]
	successCount int
}

// evalRules evaluates a slice of rules and collects the results along with the
// number of successes and a set of matched trust anchors.
func evalRules(ctx *EvalContext, rules []Rule) evalRulesResult {
	matched := emptyStringSet()
	successCount := 0
	results := make([]EvalResult, len(rules))

	for i, rule := range rules {
		result := rule.Eval(ctx)

		if result.Success {
			matched.InsertSet(result.Matched)
			successCount++
		}

		results[i] = result
	}

	return evalRulesResult{results, matched, successCount}
}

// emptyStringSet is a helper to create an empty string set. This is mainly
// used to avoid verbose type hints at the call sites because set.From returns
// a set.Set, but we actually work with the set.Collection interface.
func emptyStringSet() set.Collection[string] {
	return set.From([]string{})
}
