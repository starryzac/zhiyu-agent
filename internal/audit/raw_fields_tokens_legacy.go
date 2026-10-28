//go:build !goexperiment.jsonv2

package audit

import (
	"bytes"
	"encoding/json"
)

// The non-experiment build keeps the complete original V1 token source.
type selectedRawTokens struct{ decoder *json.Decoder }

func newSelectedRawTokens(raw []byte) *selectedRawTokens {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return &selectedRawTokens{decoder: decoder}
}

func (source *selectedRawTokens) Token(_ bool) (json.Token, error) { return source.decoder.Token() }
func (source *selectedRawTokens) More() bool                       { return source.decoder.More() }
