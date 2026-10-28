//go:build goexperiment.jsonv2

package audit

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
)

// This local token source preserves V1's lexer settings and More/error choices.
// No borrowed Token survives a decoder operation or leaves Token below.
type selectedRawTokens struct {
	decoder *jsontext.Decoder
	err     error
}

func newSelectedRawTokens(raw []byte) *selectedRawTokens {
	return &selectedRawTokens{decoder: jsontext.NewDecoder(bytes.NewReader(raw), json.DefaultOptionsV1(), jsontext.AllowDuplicateNames(true))}
}

func (source *selectedRawTokens) Token(retain bool) (json.Token, error) {
	if source.err != nil {
		return nil, source.err
	}
	token, err := source.decoder.ReadToken()
	if err != nil {
		return nil, err
	}
	switch kind := token.Kind(); kind {
	case 'n':
		return nil, nil
	case 'f':
		return false, nil
	case 't':
		return true, nil
	case '"':
		if !retain {
			return rawUnretainedString{}, nil
		}
		return token.String(), nil
	case '0':
		return json.Number(token.String()), nil
	case '{', '}', '[', ']':
		return json.Delim(kind), nil
	default:
		panic("unreachable")
	}
}

func (source *selectedRawTokens) More() bool {
	kind := source.decoder.PeekKind()
	if kind == 0 {
		if source.err == nil {
			_, err := source.decoder.ReadToken()
			if err == nil {
				err = errors.New("json: successful read after failed peek")
			}
			source.err = err
		}
		return source.err != io.EOF
	}
	return kind != ']' && kind != '}'
}
