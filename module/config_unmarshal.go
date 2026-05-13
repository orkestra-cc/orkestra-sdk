package module

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/orkestra/backend/internal/shared/utils"
)

// UnmarshalModule decodes the active-environment configuration of moduleName
// into v, which must be a non-nil pointer to a struct. Resolution order per
// field matches GetValue/GetSecret: active-environment value → schema default
// → schema EnvVar.
//
// Field-to-key mapping:
//   - Explicit `module:"keyName"` tag on the struct field wins.
//   - Otherwise the struct field name is lowercased-first-rune (PascalCase →
//     camelCase). E.g. APIKey → aPIKey; declare a tag if your schema uses a
//     different convention (most schemas do).
//   - Unexported fields and fields tagged `module:"-"` are ignored.
//   - Fields whose mapped key has no entry in the schema are left at their Go
//     zero value (no error). This matches the silent-default behaviour of the
//     existing GetValue helpers.
//
// FieldSecret values are decrypted via utils.DecryptOAuthToken (AES-256-GCM,
// same path as GetSecret). A decryption failure surfaces as an error.
//
// Type compatibility between Go struct field and schema field type:
//
//	schema FieldString     → string
//	schema FieldBool       → bool
//	schema FieldInt        → int, int32, int64
//	schema FieldDuration   → time.Duration
//	schema FieldSecret     → string
//	schema FieldEnum       → string (value validated against Options)
//	schema FieldStringList → []string (comma-separated; empty string → nil)
//
// Any other pairing returns an error naming the offending field.
func (s *ModuleConfigService) UnmarshalModule(ctx context.Context, moduleName string, v any) error {
	doc, err := s.repo.FindByName(ctx, moduleName)
	if err != nil {
		return fmt.Errorf("UnmarshalModule: load %q: %w", moduleName, err)
	}
	return unmarshalFromDoc(moduleName, doc, v)
}

// unmarshalFromDoc is the pure, repo-independent core of UnmarshalModule.
// Exposed at package level so tests can exercise the reflection / coercion
// logic without a MongoDB fixture.
func unmarshalFromDoc(moduleName string, doc *ModuleConfig, v any) error {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("UnmarshalModule: v must be a non-nil pointer, got %T", v)
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("UnmarshalModule: v must point to a struct, got pointer to %s", elem.Kind())
	}

	var (
		schema    []ConfigField
		values    map[string]string
		encrypted map[string]string
	)
	if doc != nil {
		schema = doc.ConfigSchema
		values = doc.ActiveConfigValues()
		encrypted = doc.ActiveEncryptedValues()
	}
	schemaByKey := make(map[string]ConfigField, len(schema))
	for _, f := range schema {
		schemaByKey[f.Key] = f
	}

	t := elem.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		key := schemaKeyForField(sf)
		if key == "" {
			continue
		}
		field, ok := schemaByKey[key]
		if !ok {
			// No schema entry — leave the Go zero value.
			continue
		}
		raw, err := resolveValue(field, values, encrypted)
		if err != nil {
			return fmt.Errorf("UnmarshalModule %q field %q: %w", moduleName, sf.Name, err)
		}
		if err := assignField(elem.Field(i), sf, field, raw); err != nil {
			return fmt.Errorf("UnmarshalModule %q field %q: %w", moduleName, sf.Name, err)
		}
	}
	return nil
}

// schemaKeyForField returns the schema key the struct field maps to. An
// explicit `module:"..."` tag wins; a `module:"-"` tag skips the field.
// Otherwise the field name's first rune is lowercased and the rest preserved
// (PascalCase → camelCase). Anonymous (embedded) fields without an explicit
// tag are skipped — embedding is rare in config structs and treating each
// embedded field would create surprising key collisions.
func schemaKeyForField(sf reflect.StructField) string {
	if tag, ok := sf.Tag.Lookup("module"); ok {
		if tag == "-" {
			return ""
		}
		// Allow `module:"key,omitempty"` style tags by trimming options.
		if comma := strings.IndexByte(tag, ','); comma >= 0 {
			tag = tag[:comma]
		}
		if tag != "" {
			return tag
		}
	}
	if sf.Anonymous {
		return ""
	}
	name := sf.Name
	if name == "" {
		return ""
	}
	runes := []rune(name)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

// resolveValue applies the GetValue/GetSecret precedence to a single field:
// active-env value (decrypted for secrets) → schema default → env var.
// Returns the raw string ready for type coercion.
func resolveValue(field ConfigField, values, encrypted map[string]string) (string, error) {
	if field.Type == FieldSecret {
		if enc, ok := encrypted[field.Key]; ok && enc != "" {
			plain, err := utils.DecryptOAuthToken(enc)
			if err != nil {
				return "", fmt.Errorf("decrypt secret: %w", err)
			}
			return plain, nil
		}
	} else {
		if v, ok := values[field.Key]; ok && v != "" {
			return v, nil
		}
	}
	if field.EnvVar != "" {
		if v := os.Getenv(field.EnvVar); v != "" {
			return v, nil
		}
	}
	return field.Default, nil
}

// assignField writes raw into target, coercing based on the schema field type
// and the struct field's Go kind. Returns an error if the pairing is
// unsupported or the raw value cannot be parsed.
func assignField(target reflect.Value, sf reflect.StructField, field ConfigField, raw string) error {
	if !target.CanSet() {
		return fmt.Errorf("cannot set field")
	}

	switch field.Type {
	case FieldString, FieldSecret:
		if target.Kind() != reflect.String {
			return fmt.Errorf("schema type %s requires string field, got %s", field.Type, target.Kind())
		}
		target.SetString(raw)

	case FieldEnum:
		if target.Kind() != reflect.String {
			return fmt.Errorf("schema type %s requires string field, got %s", field.Type, target.Kind())
		}
		if raw != "" && len(field.Options) > 0 {
			ok := false
			for _, opt := range field.Options {
				if opt == raw {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("value %q not in enum options %v", raw, field.Options)
			}
		}
		target.SetString(raw)

	case FieldBool:
		if target.Kind() != reflect.Bool {
			return fmt.Errorf("schema type bool requires bool field, got %s", target.Kind())
		}
		target.SetBool(parseBool(raw))

	case FieldInt:
		switch target.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if raw == "" {
				target.SetInt(0)
				return nil
			}
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return fmt.Errorf("parse int %q: %w", raw, err)
			}
			if target.OverflowInt(n) {
				return fmt.Errorf("int value %d overflows %s", n, target.Kind())
			}
			target.SetInt(n)
		default:
			return fmt.Errorf("schema type int requires int field, got %s", target.Kind())
		}

	case FieldDuration:
		if target.Type() != reflect.TypeOf(time.Duration(0)) {
			return fmt.Errorf("schema type duration requires time.Duration field, got %s", target.Type())
		}
		if raw == "" {
			target.Set(reflect.ValueOf(time.Duration(0)))
			return nil
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", raw, err)
		}
		target.Set(reflect.ValueOf(d))

	case FieldStringList:
		if target.Kind() != reflect.Slice || target.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("schema type stringList requires []string field, got %s", target.Type())
		}
		if raw == "" {
			target.Set(reflect.Zero(target.Type()))
			return nil
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		target.Set(reflect.ValueOf(out))

	default:
		return fmt.Errorf("unknown schema field type %q", field.Type)
	}
	return nil
}

// parseBool matches the existing GetConfigBool semantics from Dependencies.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
