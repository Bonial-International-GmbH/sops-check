package rules

// AllOfRule asserts that all of the nested rules match.
type AllOfRule struct {
	metaRule
	rules []Rule
}

// AllOf creates an AllOfRule from zero or more rules.
func AllOf(rules ...Rule) *AllOfRule {
	return &AllOfRule{rules: rules}
}

// Kind implements Rule.
func (*AllOfRule) Kind() Kind {
	return KindAllOf
}

// Eval implements Rule.
func (r *AllOfRule) Eval(ctx *EvalContext) EvalResult {
	rules := ctx.filterRules(r.rules)
	result := evalRules(ctx, rules)

	return EvalResult{
		Rule:      r,
		Success:   result.successCount == len(rules),
		Matched:   result.matched,
		Unmatched: ctx.TrustAnchors.Difference(result.matched),
		Nested:    result.results,
	}
}
