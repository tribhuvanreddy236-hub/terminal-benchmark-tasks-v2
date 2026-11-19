package policy

// ResolveBools applies scenario defaults and policy_overrides.
func ResolveBools(requireToken, blockPartner bool, overrides map[string]interface{}) (bool, bool) {
	if overrides == nil {
		return requireToken, blockPartner
	}
	if v, ok := overrides["require_token_on_internal"]; ok {
		if b, ok := toBool(v); ok {
			requireToken = b
		}
	}
	if v, ok := overrides["block_partner_to_privileged"]; ok {
		if b, ok := toBool(v); ok {
			blockPartner = b
		}
	}
	return requireToken, blockPartner
}

func toBool(v interface{}) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	default:
		return false, false
	}
}
