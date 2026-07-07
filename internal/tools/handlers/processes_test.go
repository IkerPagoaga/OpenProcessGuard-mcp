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
