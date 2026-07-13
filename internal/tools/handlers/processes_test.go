package handlers

import "testing"

// TestIsSensitiveEnvVar locks name-based env redaction, including the added
// connection-string / DSN names that carry credentials without a "password" or
// "secret" token in the name.
func TestIsSensitiveEnvVar(t *testing.T) {
	sensitive := []string{
		"API_TOKEN", "MY_PASSWORD", "AWS_SECRET_ACCESS_KEY", "JWT",
		"CONNECTION_STRING", "DATABASE_URL", "ODBC_DSN", "bearer_token",
	}
	for _, n := range sensitive {
		if !isSensitiveEnvVar(n) {
			t.Errorf("isSensitiveEnvVar(%q) = false, want true", n)
		}
	}
	benign := []string{"PATH", "HOMEDRIVE", "NUMBER_OF_PROCESSORS", "OS", "TEMP"}
	for _, n := range benign {
		if isSensitiveEnvVar(n) {
			t.Errorf("isSensitiveEnvVar(%q) = true, want false", n)
		}
	}
}

// TestLooksLikeSecretValue locks value-based redaction: a real credential in a
// benignly-named variable (e.g. FOO=ghp_...) is caught by its value prefix, which
// name-only matching would leak.
func TestLooksLikeSecretValue(t *testing.T) {
	secrets := []string{
		"ghp_0123456789abcdef", "github_pat_xxx", "AKIAIOSFODNN7EXAMPLE",
		"xoxb-123-abc", "sk-abcdef", "AIzaSyABC",
		"-----BEGIN RSA PRIVATE KEY-----", "eyJhbGciOiJIUzI1NiJ9", "  AKIA_leading_space",
	}
	for _, v := range secrets {
		if !looksLikeSecretValue(v) {
			t.Errorf("looksLikeSecretValue(%q) = false, want true", v)
		}
	}
	benign := []string{`C:\Windows`, "hello world", "1234", "true", "https://example.com"}
	for _, v := range benign {
		if looksLikeSecretValue(v) {
			t.Errorf("looksLikeSecretValue(%q) = true, want false", v)
		}
	}
}

// TestRedactedEnvValue locks the default-deny allowlist model that get_process_detail
// applies to env values: only an allowlisted, non-secret-named, non-secret-valued
// variable reveals its value; everything else — including an unknown-format secret in
// an unrecognised, benignly-named variable — is redacted.
func TestRedactedEnvValue(t *testing.T) {
	const redacted = "[REDACTED]"

	// Allowlisted names surface their value (case-insensitive on the name).
	shown := map[string]string{
		"PATH":                   `C:\Windows;C:\Windows\System32`,
		"OS":                     "Windows_NT",
		"processor_architecture": "AMD64", // lower-case name still matches
		"USERNAME":               "iker",
		"TEMP":                   `C:\Users\iker\AppData\Local\Temp`,
	}
	for name, val := range shown {
		if got := redactedEnvValue(name, val); got != val {
			t.Errorf("redactedEnvValue(%q, …) = %q, want the value shown", name, got)
		}
	}

	// The core leak the allowlist closes: a real secret in an UNRECOGNISED, benign
	// name with no known prefix — the old denylist would have leaked this.
	if got := redactedEnvValue("BUILD_CONFIG", "9f8c1a2b3d4e5f60718293a4b5c6d7e8"); got != redacted {
		t.Errorf("unrecognised var with a high-entropy value leaked: got %q", got)
	}
	// Any non-allowlisted name is redacted regardless of how innocuous the value is.
	if got := redactedEnvValue("SOME_APP_FLAG", "true"); got != redacted {
		t.Errorf("non-allowlisted var should be redacted, got %q", got)
	}
	// Defense in depth: an allowlisted NAME that nonetheless holds a known secret
	// value (someone stuffs a token into PATH) is still redacted.
	if got := redactedEnvValue("PATH", "ghp_0123456789abcdef"); got != redacted {
		t.Errorf("secret value in an allowlisted name should still be redacted, got %q", got)
	}
}
