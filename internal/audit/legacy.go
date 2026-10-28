package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const LegacySubjectSchema = "audit-subject-v1"
const MaxLegacySubjectBytes = 16 * 1024 * 1024

// ParseRawObject is a bounded strict JSON reader for retained originals. It
// preserves numeric lexemes as json.Number, including finite floats and -0.0.
// It does not apply new integer-only canonical rules or infer business truth.
func ParseRawObject(raw []byte) (map[string]any, error) {
	return parseRawObject(raw, nil)
}

// ParseRawObjectFields retains only the named root members, with their complete
// nested values. Every unretained value is still strictly traversed; selection
// never bypasses duplicate, numeric, byte, depth/node, UTF or EOF checks.
func ParseRawObjectFields(raw []byte, fields ...string) (map[string]any, error) {
	selected := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		selected[field] = struct{}{}
	}
	return parseRawObject(raw, selected)
}

// rawUnretainedString marks an already validated string value without its payload.
// The walker discards it; keys and retained values always use owned Go strings.
type rawUnretainedString struct{}

func parseRawObject(raw []byte, selected map[string]struct{}) (map[string]any, error) {
	if len(raw) > MaxLegacySubjectBytes || !utf8.Valid(raw) || !validSurrogates(raw) {
		return nil, ErrInvalid
	}
	var nextToken func(bool) (json.Token, error)
	var more func() bool
	if selected == nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		nextToken = func(bool) (json.Token, error) { return decoder.Token() }
		more = decoder.More
	} else {
		decoder := newSelectedRawTokens(raw)
		nextToken = decoder.Token
		more = decoder.More
	}
	nodes := 0
	var read func(int, bool) (any, error)
	read = func(depth int, retain bool) (any, error) {
		nodes++
		if depth > 64 || nodes > 1000000 {
			return nil, fmt.Errorf("%w: raw JSON bounds", ErrInvalid)
		}
		token, err := nextToken(retain)
		if err != nil {
			return nil, fmt.Errorf("%w: raw JSON syntax", ErrInvalid)
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				var object map[string]any
				if retain {
					object = map[string]any{}
				}
				// Unretained objects still remember every key for duplicate rejection.
				// The full-retention path uses the original object map for that check.
				var seen map[string]struct{}
				if !retain || depth == 0 && selected != nil {
					seen = map[string]struct{}{}
				}
				for more() {
					keyToken, err := nextToken(true)
					if err != nil {
						return nil, ErrInvalid
					}
					key, ok := keyToken.(string)
					if !ok {
						return nil, ErrInvalid
					}
					if seen != nil {
						if _, exists := seen[key]; exists {
							return nil, fmt.Errorf("%w: duplicate raw key", ErrInvalid)
						}
						seen[key] = struct{}{}
					} else if _, exists := object[key]; exists {
						return nil, fmt.Errorf("%w: duplicate raw key", ErrInvalid)
					}
					keepChild := retain
					if depth == 0 && selected != nil {
						_, keepChild = selected[key]
					}
					child, err := read(depth+1, keepChild)
					if err != nil {
						return nil, err
					}
					if keepChild {
						object[key] = child
					}
				}
				end, err := nextToken(false)
				if err != nil || end != json.Delim('}') {
					return nil, ErrInvalid
				}
				return object, nil
			case '[':
				var array []any
				if retain {
					array = []any{}
				}
				for more() {
					child, err := read(depth+1, retain)
					if err != nil {
						return nil, err
					}
					if retain {
						array = append(array, child)
					}
				}
				end, err := nextToken(false)
				if err != nil || end != json.Delim(']') {
					return nil, ErrInvalid
				}
				return array, nil
			}
			return nil, ErrInvalid
		case json.Number:
			if _, err := legacyNumber(value); err != nil {
				return nil, err
			}
			return value, nil
		case rawUnretainedString:
			return nil, nil
		case nil, bool, string:
			return value, nil
		default:
			return nil, ErrInvalid
		}
	}
	value, err := read(0, true)
	if err != nil {
		return nil, err
	}
	if _, err = nextToken(false); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing raw JSON", ErrInvalid)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return object, nil
}

// legacyNumber reproduces Python's finite JSON float spelling for this legacy
// protocol; integer strings are arbitrary precision and retain integer type.
// The original is hashed directly only after its old canonical spelling is
// checked. It is never replaced by a new-protocol canonical original.
func legacyNumber(number json.Number) (string, error) {
	lexeme := number.String()
	if !strings.ContainsAny(lexeme, ".eE") {
		n, ok := new(big.Int).SetString(lexeme, 10)
		if !ok {
			return "", ErrInvalid
		}
		return n.String(), nil
	}
	value, err := strconv.ParseFloat(lexeme, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return "", fmt.Errorf("%w: legacy nonfinite float", ErrInvalid)
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	index := strings.LastIndexByte(scientific, 'e')
	exponent, _ := strconv.Atoi(scientific[index+1:])
	if exponent >= -4 && exponent < 16 {
		fixed := strconv.FormatFloat(value, 'f', -1, 64)
		if !strings.ContainsRune(fixed, '.') {
			fixed += ".0"
		}
		return fixed, nil
	}
	return scientific, nil
}

func legacyCanonical(value map[string]any) ([]byte, error) {
	var buffer bytes.Buffer
	var encode func(any) error
	encode = func(item any) error {
		switch value := item.(type) {
		case nil:
			buffer.WriteString("null")
		case bool:
			buffer.WriteString(strconv.FormatBool(value))
		case string:
			writeString(&buffer, value)
		case json.Number:
			encoded, err := legacyNumber(value)
			if err != nil {
				return err
			}
			buffer.WriteString(encoded)
		case []any:
			buffer.WriteByte('[')
			for i, child := range value {
				if i > 0 {
					buffer.WriteByte(',')
				}
				if err := encode(child); err != nil {
					return err
				}
			}
			buffer.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			buffer.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					buffer.WriteByte(',')
				}
				writeString(&buffer, key)
				buffer.WriteByte(':')
				if err := encode(value[key]); err != nil {
					return err
				}
			}
			buffer.WriteByte('}')
		default:
			return ErrInvalid
		}
		return nil
	}
	if err := encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type LegacySubject struct {
	SchemaVersion    string
	CanonicalVersion string
	Simulation       bool
	UserID           string
	EpochID          string
	Kind             string
	ID               string
	Scope            string
	SnapshotVersion  int64
	Data             map[string]any
}

type LegacyValidator func(LegacySubject) error
type legacyKey struct {
	kind    string
	version int64
}
type LegacyRegistry struct{ validators map[legacyKey]LegacyValidator }

func NewLegacyRegistry() *LegacyRegistry {
	return &LegacyRegistry{validators: map[legacyKey]LegacyValidator{}}
}
func (r *LegacyRegistry) Register(kind string, version int64, validator LegacyValidator) error {
	if r == nil || !label(kind) || version < 1 || validator == nil {
		return ErrInvalid
	}
	if r.validators == nil {
		r.validators = map[legacyKey]LegacyValidator{}
	}
	key := legacyKey{kind, version}
	if r.validators[key] != nil {
		return fmt.Errorf("%w: duplicate legacy validator", ErrInvalid)
	}
	r.validators[key] = validator
	return nil
}

var legacyUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DecodeLegacySubject checks the exact historical header, raw canonical bytes,
// explicit kind/version registration and injected row validator. The resulting
// digest belongs to the untouched old bytes under their original namespace.
// Valid raw EVIDENCE content may itself record an invalid claim; it confers no
// financial authority and is never rewritten into a successful outcome.
func DecodeLegacySubject(raw []byte, registry *LegacyRegistry) (LegacySubject, string, error) {
	var subject LegacySubject
	value, err := ParseRawObject(raw)
	if err != nil {
		return subject, "", err
	}
	if value["schema_version"] != LegacySubjectSchema || value["canonical_version"] != LegacyCanonicalVersion {
		return subject, "", ErrUnsupportedVersion
	}
	if len(value) != 10 {
		return subject, "", fmt.Errorf("%w: legacy header fields", ErrInvalid)
	}
	fields := map[string]string{}
	for _, key := range []string{"user_id", "epoch_id", "kind", "id", "scope"} {
		text, ok := value[key].(string)
		if !ok || !label(text) {
			return subject, "", ErrInvalid
		}
		fields[key] = text
	}
	for _, key := range []string{"user_id", "epoch_id", "id"} {
		if !legacyUUID.MatchString(fields[key]) {
			return subject, "", ErrInvalid
		}
	}
	if value["simulation"] != true {
		return subject, "", ErrInvalid
	}
	versionNumber, ok := value["snapshot_version"].(json.Number)
	if !ok {
		return subject, "", ErrInvalid
	}
	version, err := integer(versionNumber)
	if err != nil || version < 1 {
		return subject, "", ErrInvalid
	}
	data, ok := value["data"].(map[string]any)
	if !ok || data["id"] != fields["id"] {
		return subject, "", ErrInvalid
	}
	if fields["scope"] == "GLOBAL_CATALOG" {
		if fields["kind"] != "ASSET_PRODUCT" || data["user_id"] != nil {
			return subject, "", ErrInvalid
		}
	} else if fields["scope"] != "TENANT" {
		return subject, "", ErrInvalid
	} else if fields["kind"] == "USER" {
		if fields["id"] != fields["user_id"] {
			return subject, "", ErrInvalid
		}
	} else if data["user_id"] != fields["user_id"] {
		return subject, "", ErrInvalid
	}
	for key, money := range data {
		if strings.HasSuffix(key, "_cents") && money != nil {
			number, ok := money.(json.Number)
			if !ok {
				return subject, "", ErrInvalid
			}
			if _, err = integer(number); err != nil {
				return subject, "", err
			}
		}
	}
	subject = LegacySubject{SchemaVersion: LegacySubjectSchema, CanonicalVersion: LegacyCanonicalVersion, Simulation: true, UserID: fields["user_id"], EpochID: fields["epoch_id"], Kind: fields["kind"], ID: fields["id"], Scope: fields["scope"], SnapshotVersion: version, Data: data}
	if registry == nil || registry.validators[legacyKey{subject.Kind, version}] == nil {
		return subject, "", ErrUnsupportedVersion
	}
	if err = registry.validators[legacyKey{subject.Kind, version}](subject); err != nil {
		return subject, "", err
	}
	canonical, err := legacyCanonical(value)
	if err != nil {
		return subject, "", err
	}
	if !bytes.Equal(canonical, raw) {
		return subject, "", fmt.Errorf("%w: original legacy canonical bytes differ", ErrInvalid)
	}
	return subject, digestBytes("bounded-funds/audit-subject-v1\x00", raw), nil
}

func VerifyLegacyOriginal(original Original, registry *LegacyRegistry) (LegacySubject, error) {
	subject, digest, err := DecodeLegacySubject(original.Canonical, registry)
	if err != nil {
		return subject, err
	}
	if !validDigest(original.Digest) || digest != original.Digest {
		return subject, fmt.Errorf("%w: legacy original digest differs", ErrInvalid)
	}
	return subject, nil
}

// LegacyConfigurationDigest reproduces the old configuration_hash algorithm
// (Python raw finite JSON, sorted keys, no prefix). This is a byte/hash adapter,
// not an economic validator or an import of any authorization. Subject
// originals must use DecodeLegacySubject and their own original namespace.
func LegacyConfigurationDigest(raw []byte) (string, error) {
	value, err := ParseRawObject(raw)
	if err != nil {
		return "", err
	}
	canonical, err := legacyCanonical(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

// LegacyStatus maps protocol errors without treating unsupported originals as
// valid, or interpreting a raw claim's content as its financial outcome.
func LegacyStatus(err error) Status {
	if err == nil {
		return Valid
	}
	if errors.Is(err, ErrUnsupportedVersion) {
		return UnsupportedVersion
	}
	return Invalid
}
