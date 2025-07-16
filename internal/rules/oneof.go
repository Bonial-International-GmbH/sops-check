package rules

// OneOfRule asserts that exactly one of the nested rules matches.
type OneOfRule struct {
	metaRule
	rules []Rule
}

// OneOf creates a OneOfRule from zero or more rules.
func OneOf(rules ...Rule) *OneOfRule {
	return &OneOfRule{rules: rules}
}

// Kind implements Rule.
func (*OneOfRule) Kind() Kind {
	return KindOneOf
}

// Eval implements Rule.
func (r *OneOfRule) Eval(ctx *EvalContext) EvalResult {
	result := evalRules(ctx, ctx.filterRules(r.rules))

	return EvalResult{
		Rule:      r,
		Success:   result.successCount == 1,
		Matched:   result.matched,
		Unmatched: ctx.TrustAnchors.Difference(result.matched),
		Nested:    result.results,
	}
}
