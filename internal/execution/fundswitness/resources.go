package fundswitness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RowSet retains the exact SQL jsonb::text strings, not reencoded objects.
type RowSet map[string]map[string]string

func StateHash(rows RowSet) string {
	tables := make([]string, 0, len(rows))
	for table := range rows {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var frame strings.Builder
	for _, table := range tables {
		keys := make([]string, 0, len(rows[table]))
		for key := range rows[table] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			hash := sha256.Sum256([]byte(rows[table][key]))
			frame.WriteString(table + "\t" + key + "\t" + hex.EncodeToString(hash[:]) + "\n")
		}
	}
	hash := sha256.Sum256([]byte(frame.String()))
	return hex.EncodeToString(hash[:])
}

func RowCount(rows RowSet) int {
	n := 0
	for _, values := range rows {
		n += len(values)
	}
	return n
}

// OperationResources selects every original RESERVED resource and immutable
// income claim of this exact operation in the BEFORE FV. It never selects a
// present-day ledger or accepts a caller supplied subset of the vector.
func OperationResources(before RowSet, kind, operation string) (RowSet, error) {
	if operation == "" || kind != "LEGACY" && kind != "NATIVE" {
		return nil, fmt.Errorf("terminal resource ledger/operation")
	}
	reservation, claims := "income_reservations", "income_claims"
	tables := []string{reservation, claims}
	if kind == "NATIVE" {
		reservation, claims = "native_income_reservations", "native_income_claims"
		tables = []string{reservation, claims, "native_holds", "native_return_claims"}
	}
	active := false
	for _, raw := range before[reservation] {
		var value map[string]any
		if json.Unmarshal([]byte(raw), &value) != nil {
			return nil, fmt.Errorf("terminal reservation original JSON")
		}
		if value["action_id"] == operation && value["state"] == "RESERVED" {
			active = true
		}
	}
	out := RowSet{}
	for _, table := range tables {
		for key, raw := range before[table] {
			var value map[string]any
			if json.Unmarshal([]byte(raw), &value) != nil {
				return nil, fmt.Errorf("terminal resource original JSON")
			}
			id, _ := value["operation_id"].(string)
			if id == "" {
				id, _ = value["action_id"].(string)
			}
			if id != operation || table == claims && !active || table != claims && value["state"] != "RESERVED" {
				continue
			}
			if out[table] == nil {
				out[table] = map[string]string{}
			}
			out[table][key] = raw
		}
	}
	return out, nil
}
