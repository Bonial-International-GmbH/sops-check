package rules

// AnyOfRule asserts that at least one of the nested rules matches.
type AnyOfRule struct {
	metaRule
	rules []Rule
}

// AnyOf creates an AnyOfRule from zero or more rules.
func AnyOf(rules ...Rule) *AnyOfRule {
	return &AnyOfRule{rules: rules}
}

// Kind implements Rule.
func (*AnyOfRule) Kind() Kind {
	return KindAnyOf
}

// Eval implements Rule.
func (r *AnyOfRule) Eval(ctx *EvalContext) EvalResult {
	result := evalRules(ctx, ctx.filterRules(r.rules))

	return EvalResult{
		Rule:      r,
		Success:   result.successCount > 0,
		Matched:   result.matched,
		Unmatched: ctx.TrustAnchors.Difference(result.matched),
		Nested:    result.results,
	}
}
