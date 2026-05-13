package module

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/orkestra/backend/internal/shared/utils"
)

// testEncryptionKey is a deterministic 32-byte hex string used by the secret
// fields tests. utils.EncryptOAuthToken/DecryptOAuthToken read the key from
// OAUTH_TOKEN_ENCRYPTION_KEY at call time.
const testEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// withEncryptionKey installs the test key for the lifetime of t.
func withEncryptionKey(t *testing.T) {
	t.Helper()
	t.Setenv("OAUTH_TOKEN_ENCRYPTION_KEY", testEncryptionKey)
}

// docWith builds a ModuleConfig with the given schema and a single
// "production" environment carrying the supplied values + encrypted values.
// Active environment defaults to production.
func docWith(schema []ConfigField, values, encrypted map[string]string) *ModuleConfig {
	return &ModuleConfig{
		ModuleName:        "test",
		ConfigSchema:      schema,
		ActiveEnvironment: "production",
		Environments: map[string]EnvironmentConfig{
			"production": {ConfigValues: values, EncryptedValues: encrypted},
		},
	}
}

func TestUnmarshalModule_AllFieldTypes(t *testing.T) {
	withEncryptionKey(t)
	schema := []ConfigField{
		{Key: "apiKey", Type: FieldString},
		{Key: "enabled", Type: FieldBool},
		{Key: "maxRetries", Type: FieldInt},
		{Key: "pollInterval", Type: FieldDuration},
		{Key: "secretToken", Type: FieldSecret},
		{Key: "logLevel", Type: FieldEnum, Options: []string{"debug", "info", "warn"}},
		{Key: "tags", Type: FieldStringList},
	}
	enc, err := utils.EncryptOAuthToken("hunter2")
	if err != nil {
		t.Fatalf("encrypt setup: %v", err)
	}
	doc := docWith(schema,
		map[string]string{
			"apiKey":       "abc",
			"enabled":      "true",
			"maxRetries":   "5",
			"pollInterval": "30s",
			"logLevel":     "info",
			"tags":         "a, b , c",
		},
		map[string]string{"secretToken": enc},
	)

	var got struct {
		APIKey       string        `module:"apiKey"`
		Enabled      bool          `module:"enabled"`
		MaxRetries   int           `module:"maxRetries"`
		PollInterval time.Duration `module:"pollInterval"`
		SecretToken  string        `module:"secretToken"`
		LogLevel     string        `module:"logLevel"`
		Tags         []string      `module:"tags"`
	}
	if err := unmarshalFromDoc("test", doc, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.APIKey != "abc" {
		t.Errorf("APIKey = %q, want abc", got.APIKey)
	}
	if !got.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	if got.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", got.MaxRetries)
	}
	if got.PollInterval != 30*time.Second {
		t.Errorf("PollInterval = %v, want 30s", got.PollInterval)
	}
	if got.SecretToken != "hunter2" {
		t.Errorf("SecretToken = %q, want hunter2 (decrypted)", got.SecretToken)
	}
	if got.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", got.LogLevel)
	}
	wantTags := []string{"a", "b", "c"}
	if len(got.Tags) != len(wantTags) {
		t.Errorf("Tags = %v, want %v", got.Tags, wantTags)
	}
	for i := range wantTags {
		if got.Tags[i] != wantTags[i] {
			t.Errorf("Tags[%d] = %q, want %q", i, got.Tags[i], wantTags[i])
			break
		}
	}
}

func TestUnmarshalModule_SecretDecryption(t *testing.T) {
	withEncryptionKey(t)
	enc, err := utils.EncryptOAuthToken("super-secret-token")
	if err != nil {
		t.Fatalf("encrypt setup: %v", err)
	}
	schema := []ConfigField{{Key: "apiKey", Type: FieldSecret}}
	doc := docWith(schema, nil, map[string]string{"apiKey": enc})

	var out struct {
		APIKey string `module:"apiKey"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.APIKey != "super-secret-token" {
		t.Errorf("APIKey = %q, want decrypted plaintext", out.APIKey)
	}
}

func TestUnmarshalModule_SecretDecryptionFailure(t *testing.T) {
	withEncryptionKey(t)
	schema := []ConfigField{{Key: "apiKey", Type: FieldSecret}}
	// Garbage ciphertext that won't decrypt.
	doc := docWith(schema, nil, map[string]string{"apiKey": "not-valid-base64-or-aes"})

	var out struct {
		APIKey string `module:"apiKey"`
	}
	err := unmarshalFromDoc("test", doc, &out)
	if err == nil {
		t.Fatalf("expected decrypt error, got nil")
	}
	if !strings.Contains(err.Error(), "APIKey") || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("error should mention APIKey field and decrypt: %v", err)
	}
}

func TestUnmarshalModule_EnumRejectsBadValue(t *testing.T) {
	schema := []ConfigField{{Key: "logLevel", Type: FieldEnum, Options: []string{"debug", "info"}}}
	doc := docWith(schema, map[string]string{"logLevel": "trace"}, nil)

	var out struct {
		LogLevel string `module:"logLevel"`
	}
	err := unmarshalFromDoc("test", doc, &out)
	if err == nil {
		t.Fatalf("expected enum-rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "trace") || !strings.Contains(err.Error(), "enum") {
		t.Errorf("error should explain enum mismatch: %v", err)
	}
}

func TestUnmarshalModule_EnumAcceptsEmpty(t *testing.T) {
	// Enum with no value and no default — should not error; field stays empty.
	schema := []ConfigField{{Key: "logLevel", Type: FieldEnum, Options: []string{"debug", "info"}}}
	doc := docWith(schema, nil, nil)

	var out struct {
		LogLevel string `module:"logLevel"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("empty enum should not error: %v", err)
	}
	if out.LogLevel != "" {
		t.Errorf("LogLevel = %q, want empty", out.LogLevel)
	}
}

func TestUnmarshalModule_SchemaDefaultFallback(t *testing.T) {
	schema := []ConfigField{
		{Key: "host", Type: FieldString, Default: "localhost"},
		{Key: "port", Type: FieldInt, Default: "8080"},
	}
	doc := docWith(schema, map[string]string{}, nil)

	var out struct {
		Host string `module:"host"`
		Port int    `module:"port"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Host != "localhost" {
		t.Errorf("Host = %q, want localhost (default)", out.Host)
	}
	if out.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (default)", out.Port)
	}
}

func TestUnmarshalModule_EnvVarFallback(t *testing.T) {
	t.Setenv("TEST_UNMARSHAL_HOST", "env-host")
	schema := []ConfigField{
		{Key: "host", Type: FieldString, EnvVar: "TEST_UNMARSHAL_HOST", Default: "fallback-host"},
	}
	doc := docWith(schema, map[string]string{}, nil)

	var out struct {
		Host string `module:"host"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Host != "env-host" {
		t.Errorf("Host = %q, want env-host (env var should win over default)", out.Host)
	}
}

func TestUnmarshalModule_DBValueWinsOverEnvAndDefault(t *testing.T) {
	t.Setenv("TEST_UNMARSHAL_HOST", "env-host")
	schema := []ConfigField{
		{Key: "host", Type: FieldString, EnvVar: "TEST_UNMARSHAL_HOST", Default: "fallback-host"},
	}
	doc := docWith(schema, map[string]string{"host": "db-host"}, nil)

	var out struct {
		Host string `module:"host"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Host != "db-host" {
		t.Errorf("Host = %q, want db-host (DB should win)", out.Host)
	}
}

func TestUnmarshalModule_TagOverridesAutoMapping(t *testing.T) {
	// Struct field "OAuthBaseURL" would auto-map to "oAuthBaseURL"; the schema
	// uses the more idiomatic "oauthBaseURL". The tag bridges them.
	schema := []ConfigField{{Key: "oauthBaseURL", Type: FieldString}}
	doc := docWith(schema, map[string]string{"oauthBaseURL": "https://example.com"}, nil)

	var out struct {
		OAuthBaseURL string `module:"oauthBaseURL"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.OAuthBaseURL != "https://example.com" {
		t.Errorf("OAuthBaseURL = %q, want https://example.com", out.OAuthBaseURL)
	}
}

func TestUnmarshalModule_AutoMappingDefault(t *testing.T) {
	// Without a tag, PascalCase struct field maps to camelCase schema key by
	// lowercasing the first rune only.
	schema := []ConfigField{{Key: "apiKey", Type: FieldString}}
	doc := docWith(schema, map[string]string{"apiKey": "from-auto"}, nil)

	var out struct {
		ApiKey string // → "apiKey"  (first rune lowercased)
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ApiKey != "from-auto" {
		t.Errorf("ApiKey = %q, want from-auto", out.ApiKey)
	}
}

func TestUnmarshalModule_DashTagSkipsField(t *testing.T) {
	schema := []ConfigField{{Key: "skipMe", Type: FieldString, Default: "would-be-set"}}
	doc := docWith(schema, nil, nil)

	var out struct {
		SkipMe string `module:"-"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SkipMe != "" {
		t.Errorf("SkipMe = %q, want empty (tag '-' should skip)", out.SkipMe)
	}
}

func TestUnmarshalModule_UnexportedFieldsIgnored(t *testing.T) {
	schema := []ConfigField{{Key: "secret", Type: FieldString, Default: "ignored"}}
	doc := docWith(schema, nil, nil)

	// Unexported fields cannot be set by reflection; we must skip them silently.
	var out struct {
		secret string //nolint:unused
		Public string `module:"secret"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Public != "ignored" {
		t.Errorf("Public = %q, want ignored", out.Public)
	}
}

func TestUnmarshalModule_TypeMismatchErrors(t *testing.T) {
	schema := []ConfigField{{Key: "count", Type: FieldString, Default: "5"}}
	doc := docWith(schema, nil, nil)

	var out struct {
		Count int `module:"count"` // schema says string but Go field is int
	}
	err := unmarshalFromDoc("test", doc, &out)
	if err == nil {
		t.Fatalf("expected type-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "string") || !strings.Contains(err.Error(), "Count") {
		t.Errorf("error should name both the schema type and field: %v", err)
	}
}

func TestUnmarshalModule_IntParseError(t *testing.T) {
	schema := []ConfigField{{Key: "port", Type: FieldInt}}
	doc := docWith(schema, map[string]string{"port": "not-a-number"}, nil)

	var out struct {
		Port int `module:"port"`
	}
	err := unmarshalFromDoc("test", doc, &out)
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "Port") {
		t.Errorf("error should name field Port: %v", err)
	}
}

func TestUnmarshalModule_DurationParseError(t *testing.T) {
	schema := []ConfigField{{Key: "ttl", Type: FieldDuration}}
	doc := docWith(schema, map[string]string{"ttl": "5 fortnights"}, nil)

	var out struct {
		TTL time.Duration `module:"ttl"`
	}
	err := unmarshalFromDoc("test", doc, &out)
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
}

func TestUnmarshalModule_StringListEmptyAndTrim(t *testing.T) {
	schema := []ConfigField{
		{Key: "empty", Type: FieldStringList},
		{Key: "trimmed", Type: FieldStringList},
	}
	doc := docWith(schema, map[string]string{
		"empty":   "",
		"trimmed": " a ,  ,b,,c ",
	}, nil)

	var out struct {
		Empty   []string `module:"empty"`
		Trimmed []string `module:"trimmed"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Empty) != 0 {
		t.Errorf("Empty = %v, want nil/empty", out.Empty)
	}
	want := []string{"a", "b", "c"}
	if len(out.Trimmed) != len(want) {
		t.Fatalf("Trimmed = %v, want %v", out.Trimmed, want)
	}
	for i := range want {
		if out.Trimmed[i] != want[i] {
			t.Errorf("Trimmed[%d] = %q, want %q", i, out.Trimmed[i], want[i])
		}
	}
}

func TestUnmarshalModule_BoolParsing(t *testing.T) {
	schema := []ConfigField{
		{Key: "a", Type: FieldBool},
		{Key: "b", Type: FieldBool},
		{Key: "c", Type: FieldBool},
		{Key: "d", Type: FieldBool},
		{Key: "e", Type: FieldBool},
	}
	doc := docWith(schema, map[string]string{
		"a": "true",
		"b": "1",
		"c": "yes",
		"d": "false",
		"e": "garbage",
	}, nil)

	var out struct {
		A bool `module:"a"`
		B bool `module:"b"`
		C bool `module:"c"`
		D bool `module:"d"`
		E bool `module:"e"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.A || !out.B || !out.C {
		t.Errorf("true/1/yes should parse true; got A=%v B=%v C=%v", out.A, out.B, out.C)
	}
	if out.D || out.E {
		t.Errorf("false/garbage should be false; got D=%v E=%v", out.D, out.E)
	}
}

func TestUnmarshalModule_MissingSchemaKeyLeavesZero(t *testing.T) {
	// Struct has a field with no matching schema entry — should silently
	// leave the Go zero value, not error.
	schema := []ConfigField{{Key: "known", Type: FieldString, Default: "x"}}
	doc := docWith(schema, nil, nil)

	var out struct {
		Known   string `module:"known"`
		Unknown string `module:"missing"`
	}
	if err := unmarshalFromDoc("test", doc, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Known != "x" {
		t.Errorf("Known = %q, want x", out.Known)
	}
	if out.Unknown != "" {
		t.Errorf("Unknown = %q, want empty (no schema entry)", out.Unknown)
	}
}

func TestUnmarshalModule_NilDocUsesEmpty(t *testing.T) {
	// When the doc is nil (no module_configs row yet), unmarshal should
	// behave as if all values are absent — struct stays at Go zero values.
	var out struct {
		Anything string `module:"anything"`
	}
	if err := unmarshalFromDoc("test", nil, &out); err != nil {
		t.Fatalf("unmarshal nil doc should not error: %v", err)
	}
	if out.Anything != "" {
		t.Errorf("Anything = %q, want empty", out.Anything)
	}
}

func TestUnmarshalModule_RejectsNonPointer(t *testing.T) {
	doc := docWith(nil, nil, nil)
	var out struct{}
	err := unmarshalFromDoc("test", doc, out) // not a pointer
	if err == nil {
		t.Fatalf("expected error for non-pointer v")
	}
}

func TestUnmarshalModule_RejectsNilPointer(t *testing.T) {
	doc := docWith(nil, nil, nil)
	var out *struct{}
	err := unmarshalFromDoc("test", doc, out)
	if err == nil {
		t.Fatalf("expected error for nil pointer v")
	}
}

func TestUnmarshalModule_RejectsPointerToNonStruct(t *testing.T) {
	doc := docWith(nil, nil, nil)
	var s string
	err := unmarshalFromDoc("test", doc, &s)
	if err == nil {
		t.Fatalf("expected error for pointer-to-non-struct v")
	}
}

func TestUnmarshalModule_ErrorWrappingPreservesContext(t *testing.T) {
	// Confirm the error chain preserves the module name and field name so
	// callers can debug schema/struct mismatches.
	schema := []ConfigField{{Key: "port", Type: FieldInt}}
	doc := docWith(schema, map[string]string{"port": "xxx"}, nil)
	doc.ModuleName = "billing"

	var out struct {
		Port int `module:"port"`
	}
	err := unmarshalFromDoc("billing", doc, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "billing") || !strings.Contains(err.Error(), "Port") {
		t.Errorf("error should mention module and field: %v", err)
	}
	// Should still wrap the underlying strconv error.
	if errors.Unwrap(err) == nil {
		t.Errorf("error should wrap underlying cause: %v", err)
	}
}
