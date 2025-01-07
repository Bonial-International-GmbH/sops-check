package rules

import "github.com/hashicorp/go-set/v3"

// EvalContext encapsulates data needed during rule evaluation, like the trust
// anchors found within a given SOPS file.
type EvalContext struct {
	// TrustAnchors is a set of trust anchors found in a SOPS file.
	TrustAnchors set.Collection[string]
}

// NewEvalContext creates a new EvalContext from a list of trust anchors.
func NewEvalContext(trustAnchors []string) *EvalContext {
	return &EvalContext{TrustAnchors: set.From(trustAnchors)}
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
