package banksim

import "strings"

type observationRawColumn struct {
	name     string
	limit    int
	json     bool
	nullable bool
}
type observationTable struct {
	name, keys, scalars, from, where string
	raw                              []observationRawColumn
}

func observationTables() []observationTable {
	user := "t.namespace=$1 AND t.user_id=$2"
	catalog := "t.namespace=$1 AND $2::text<>''"
	raw := func(name string) []observationRawColumn { return []observationRawColumn{{name: name, limit: 131072}} }
	tables := []observationTable{
		{name: "opening_anchors", keys: "account_id", scalars: "account_id,opening_cents", where: user},
		{name: "accounts", keys: "account_id", scalars: "account_id,balance_cents,reserved_cents", where: user},
		{name: "origins", keys: "origin_id", scalars: "origin_id,original_account_id,original_cents,occurred_at,evidence_hash", where: user},
		{name: "income_locations", keys: "origin_id,account_id", scalars: "origin_id,account_id,available_cents,assigned_cents,reserved_cents,spent_cents,assigned_reserved_cents", where: user},
		{name: "goals", keys: "goal_id", scalars: "goal_id,account_id,balance_cents", where: user},
		{name: "operations", keys: "operation_key", scalars: "sequence,operation_key,operation_id,request_hash,status,version,accepted_at,available_at,settled_at,rejection_code", where: user, raw: []observationRawColumn{{name: "request", limit: 131072, json: true}}},
		{name: "postings", keys: "id", scalars: "id,operation_key,dimension,ledger_id,direction,amount_cents,occurred_at,created_at", from: "bank.postings t JOIN bank.operations o ON(o.namespace=t.namespace AND o.operation_key=t.operation_key)", where: "t.namespace=$1 AND o.user_id=$2"},
		{name: "v2_product_terms", keys: "product_id,version", scalars: "product_id,version,original_hash", where: catalog, raw: raw("original")},
		{name: "v2_product_availability", keys: "catalog_sequence", scalars: "catalog_sequence,product_id,terms_version,version,original_hash", where: catalog, raw: raw("original")},
		{name: "v2_operations", keys: "operation_key", scalars: "sequence,operation_key,operation_id,kind,business_key,request_hash,status,version,accepted_at,available_at,settled_at,rejection_code", where: user, raw: []observationRawColumn{{name: "request_original", limit: 131072}, {name: "position_original", limit: 131072, nullable: true}}},
		{name: "v2_position_openings", keys: "position_id", scalars: "position_id,opening_key,original_hash,principal_cents,product_id,terms_version,goal_id,return_account_id,purchased_at,maturity_at", where: user, raw: raw("original")},
		{name: "v2_position_state", keys: "position_id", scalars: "position_id,closing_key,closed", where: user},
		{name: "v2_goal_principal", keys: "goal_id", scalars: "goal_id,principal_cents,loss_cents", where: user},
		{name: "v2_goal_lots", keys: "goal_id,account_id,source_kind,source_id", scalars: "goal_id,account_id,source_kind,source_id,available_cents,reserved_cents", where: user},
		{name: "v2_principal_returns", keys: "operation_key", scalars: "operation_key,position_id,original_hash", where: user, raw: raw("original")},
		{name: "v2_return_locations", keys: "operation_key,account_id", scalars: "operation_key,account_id,available_cents,reserved_cents", where: user},
		{name: "v2_liability_originals", keys: "liability_id", scalars: "liability_id,original_hash,final_total_cents", where: user, raw: raw("original")},
		{name: "v2_liability_state", keys: "liability_id", scalars: "liability_id,paid_cents,reserved_cents", where: user},
		{name: "v2_quotes", keys: "quote_id", scalars: "quote_id,position_id,original_hash", where: user, raw: raw("original")},
		{name: "v2_resource_holds", keys: "operation_key,resource_kind,resource_id,resource_detail", scalars: "operation_key,resource_kind,resource_id,resource_detail,amount_cents,state", where: user},
		{name: "v2_postings", keys: "id", scalars: "id,operation_key,dimension,ledger_id,direction,amount_cents,occurred_at,created_at", from: "bank.v2_postings t JOIN bank.v2_operations o ON(o.namespace=t.namespace AND o.operation_key=t.operation_key)", where: "t.namespace=$1 AND o.user_id=$2"},
		{name: "external_credits", keys: "authority_id,event_id", scalars: "sequence,authority_id,event_id,account_id,origin_id,evidence_id,amount_cents,occurred_at,credited_at,balance_before_cents,balance_after_cents,event_hash,authority_signature_hash,record_hash,credited_xid", where: user, raw: []observationRawColumn{{name: "event_original", limit: 16384}, {name: "record_original", limit: 65536}}},
		{name: "external_credit_postings", keys: "id", scalars: "id,authority_id,event_id,leg_number,dimension,ledger_id,direction,amount_cents,occurred_at", from: "bank.external_credit_postings t JOIN bank.external_credits c ON(c.namespace=t.namespace AND c.authority_id=t.authority_id AND c.event_id=t.event_id)", where: "t.namespace=$1 AND c.user_id=$2"},
	}
	for i := range tables {
		if tables[i].from == "" {
			tables[i].from = "bank." + tables[i].name + " t"
		}
	}
	return tables
}

func observationColumns(names string) []string {
	out := []string{}
	for _, name := range strings.Split(names, ",") {
		out = append(out, "t."+name)
	}
	return out
}
