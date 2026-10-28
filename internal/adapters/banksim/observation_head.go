package banksim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
)

var errObservationUnavailable = errors.New("BANK_OBSERVATION_HEAD_UNAVAILABLE")
var observationInstance struct {
	once sync.Once
	id   string
	err  error
}

func observationInstanceID() (string, error) {
	observationInstance.once.Do(func() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			observationInstance.err = e
			return
		}
		observationInstance.id = hex.EncodeToString(b)
	})
	return observationInstance.id, observationInstance.err
}

func observationFrame(h hash.Hash, value string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(value)))
	h.Write(n[:])
	h.Write([]byte(value))
}
func observationSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func observationRawExpr(raw observationRawColumn) string {
	if raw.json {
		return "convert_to(t." + raw.name + "::text,'UTF8')"
	}
	return "t." + raw.name
}

func observationRawValid(raw observationRawColumn) string {
	valid := fmt.Sprintf("octet_length(%s) BETWEEN 1 AND %d", observationRawExpr(raw), raw.limit)
	if raw.nullable {
		return "(t." + raw.name + " IS NULL OR (" + valid + "))"
	}
	return "(" + valid + ")"
}

// A preflight contains no actual raw SHA: every scoped row/raw-byte/metadata
// bound is accepted across all tables before the second pass hashes originals.
func observationQuery(table observationTable, digest bool) string {
	key := "jsonb_build_array(" + strings.Join(observationColumns(table.keys), ",") + ")::text"
	fields := observationColumns(table.scalars)
	lens, valid := []string{}, []string{"true"}
	for _, raw := range table.raw {
		expr := observationRawExpr(raw)
		length := "CASE WHEN t." + raw.name + " IS NULL THEN -1 ELSE octet_length(" + expr + ")::bigint END"
		lens = append(lens, length)
		fields = append(fields, length)
		value := "repeat('0',64)"
		if digest {
			value = "encode(sha256(" + expr + "),'hex')"
		}
		fields = append(fields, "CASE WHEN t."+raw.name+" IS NULL THEN NULL WHEN "+observationRawValid(raw)+" THEN "+value+" ELSE NULL END")
		valid = append(valid, observationRawValid(raw))
	}
	lengths := "ARRAY[]::bigint[]"
	if len(lens) > 0 {
		lengths = "ARRAY[" + strings.Join(lens, ",") + "]::bigint[]"
	}
	meta := "jsonb_build_array(" + strings.Join(fields, ",") + ")::text"
	// The CASE is evaluated in SQL. A corrupt unbounded scalar must not cross
	// into the Go driver before the row-size marker is checked.
	rowBound := fmt.Sprintf("octet_length(m.key)+octet_length(m.meta)+%d<=16384", 24+len(table.name))
	return "SELECT octet_length(m.key),octet_length(m.meta),CASE WHEN " + rowBound + " AND m.valid THEN m.key END,CASE WHEN " + rowBound + " AND m.valid THEN m.meta END,m.raw_lengths FROM (SELECT " + key + " AS key," + meta + " AS meta,(" + strings.Join(valid, " AND ") + ") AS valid," + lengths + " AS raw_lengths FROM " + table.from + " WHERE " + table.where + " ORDER BY " + strings.Join(observationColumns(table.keys), ",") + " LIMIT 10001) m"
}

type observationPreflight struct {
	keys        map[string]bool
	rows, bytes int
	rawBytes    int64
}

func observationReadTable(ctx context.Context, tx pgx.Tx, table observationTable, namespace, user string, digest bool, hashTarget hash.Hash, budget *observationPreflight) (*observationPreflight, error) {
	rows, err := tx.Query(ctx, observationQuery(table, digest), namespace, user)
	if err != nil {
		return nil, err
	}
	out := &observationPreflight{keys: map[string]bool{}}
	for rows.Next() {
		var keyBytes, metaBytes int64
		var key, meta *string
		var lengths []int64
		if err = rows.Scan(&keyBytes, &metaBytes, &key, &meta, &lengths); err != nil {
			break
		}
		if key == nil || meta == nil || keyBytes < 0 || metaBytes < 0 || keyBytes+metaBytes+int64(24+len(table.name)) > 16384 || int64(len(*key)) != keyBytes || int64(len(*meta)) != metaBytes || len(lengths) != len(table.raw) {
			err = errObservationUnavailable
			break
		}
		if out.keys[*key] {
			err = errObservationUnavailable
			break
		}
		out.keys[*key] = true
		out.rows++
		out.bytes += int(keyBytes+metaBytes) + 24 + len(table.name)
		for i, n := range lengths {
			if n == -1 && table.raw[i].nullable {
				continue
			}
			if n < 1 || n > int64(table.raw[i].limit) {
				err = errObservationUnavailable
				break
			}
			out.rawBytes += n
		}
		if err != nil {
			break
		}
		if budget.rows+out.rows > bankcredit.ObservationHeadMaxRows || budget.bytes+out.bytes > bankcredit.ObservationHeadMaxBytes || budget.rawBytes+out.rawBytes > bankcredit.ObservationHeadMaxBytes {
			err = errObservationUnavailable
			break
		}
		if digest {
			observationFrame(hashTarget, table.name)
			observationFrame(hashTarget, *key)
			observationFrame(hashTarget, *meta)
		}
	}
	if e := rows.Err(); err == nil {
		err = e
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	budget.rows += out.rows
	budget.bytes += out.bytes
	budget.rawBytes += out.rawBytes
	return out, nil
}

func (s *Store) ObservationHead(ctx context.Context, namespace, user string, now time.Time) (bankcredit.ObservationHead, error) {
	out := bankcredit.ObservationHead{Protocol: bankcredit.ObservationHeadProtocol, Namespace: namespace, UserID: user, CapturedAt: now.UTC()}
	if !bankcredit.Scope(namespace, user) || now.IsZero() {
		return out, errObservationUnavailable
	}
	instance, err := observationInstanceID()
	if err != nil {
		return out, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	// Existing current-income/current-v2 readers use this same advisory xact
	// lock in READ ONLY. No SELECT FOR UPDATE or financial write is introduced.
	if err = userLock(ctx, tx, namespace, user); err != nil {
		return out, err
	}
	tables := observationTables()
	sort.Slice(tables, func(i, j int) bool { return tables[i].name < tables[j].name })
	out.SchemaHash, err = observationSchema(ctx, tx, tables)
	if err != nil {
		return out, err
	}
	var database string
	var oid uint32
	var postmaster time.Time
	if err = tx.QueryRow(ctx, `SELECT current_database(),oid,pg_postmaster_start_time() FROM pg_database WHERE datname=current_database()`).Scan(&database, &oid, &postmaster); err != nil {
		return out, err
	}
	out.Instance = instance
	out.BindingHash = observationSHA(instance + "/" + database + "/" + fmt.Sprint(oid) + "/" + postmaster.UTC().Format(time.RFC3339Nano) + "/" + out.SchemaHash)
	// RR may establish its snapshot while waiting for the advisory lock. This
	// is a coherent observation point, not a claim to include a writer that
	// committed while we waited. CapturedAt precedes the wait; before/after
	// heads and the next due poll retain the original eventual observation.
	headerBytes := 32 + len(out.Protocol) + len(namespace) + len(user) + len(out.BindingHash)
	first := map[string]*observationPreflight{}
	budget := &observationPreflight{bytes: headerBytes}
	for _, table := range tables {
		first[table.name], err = observationReadTable(ctx, tx, table, namespace, user, false, nil, budget)
		if err != nil {
			return out, err
		}
	}
	h := sha256.New()
	observationFrame(h, out.Protocol)
	observationFrame(h, namespace)
	observationFrame(h, user)
	observationFrame(h, out.BindingHash)
	second := &observationPreflight{bytes: headerBytes}
	for _, table := range tables {
		var part *observationPreflight
		part, err = observationReadTable(ctx, tx, table, namespace, user, true, h, second)
		if err != nil {
			return out, err
		}
		old := first[table.name]
		if part.rows != old.rows || part.bytes != old.bytes || part.rawBytes != old.rawBytes || len(part.keys) != len(old.keys) {
			return out, errObservationUnavailable
		}
		for key := range part.keys {
			if !old.keys[key] {
				return out, errObservationUnavailable
			}
		}
	}
	out.Rows = second.rows
	out.MetadataBytes = second.bytes
	out.RawBytes = second.rawBytes
	out.Digest = hex.EncodeToString(h.Sum(nil))
	if err = out.Validate(); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
