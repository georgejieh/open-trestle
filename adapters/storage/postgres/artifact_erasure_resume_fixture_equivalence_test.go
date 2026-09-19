package postgres

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestResumeFixtureValidateTablesConstraintLookupEquivalence(t *testing.T) {
	cases := []struct {
		name  string
		build func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor)
		want  string
	}{
		{
			name: "duplicate primary key composite fast tuple",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {
							{"tenant_id": "tenant", "version": int64(7)},
							{"tenant_id": "tenant", "version": int64(7)},
						},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "tenant_id", Nullable: true}, {Name: "version", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "PRIMARY KEY", Columns: []string{"tenant_id", "version"}}},
						},
					}
			},
			want: "pg:23505",
		},
		{
			name: "composite unique distinguishes nil empty string and bool type",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {
							{"tenant_id": "tenant", "variant": nil},
							{"tenant_id": "tenant", "variant": ""},
							{"tenant_id": "tenant", "variant": "false"},
							{"tenant_id": "tenant", "variant": false},
						},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "tenant_id", Nullable: true}, {Name: "variant", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"tenant_id", "variant"}}},
						},
					}
			},
			want: "nil",
		},
		{
			name: "string length check failure",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"tenant_id": strings.Repeat("x", 129)}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "tenant_id", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "CHECK", Expression: "octet_length(tenant_id) BETWEEN 1 AND 128"}},
						},
					}
			},
			want: "pg:23514",
		},
		{
			name: "not null precedes check constraint",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"tenant_id": nil}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "tenant_id", Nullable: false}},
							Constraints: []erasureConstraint{{Kind: "CHECK", Expression: "octet_length(tenant_id) BETWEEN 1 AND 128"}},
						},
					}
			},
			want: "pg:23502",
		},
		{
			name: "foreign key null bypass",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_parent": nil,
						"fixture_child":  {{"parent_id": nil}},
					}, map[string]erasureTableDescriptor{
						"fixture_parent": {Columns: []erasureColumn{{Name: "id", Nullable: true}}},
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "parent_id", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "FOREIGN KEY", Columns: []string{"parent_id"}, Target: "fixture_parent", TargetColumns: []string{"id"}}},
						},
					}
			},
			want: "nil",
		},
		{
			name: "foreign key fast match",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_parent": {{"id": "parent"}},
						"fixture_child":  {{"parent_id": "parent"}},
					}, map[string]erasureTableDescriptor{
						"fixture_parent": {Columns: []erasureColumn{{Name: "id", Nullable: true}}},
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "parent_id", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "FOREIGN KEY", Columns: []string{"parent_id"}, Target: "fixture_parent", TargetColumns: []string{"id"}}},
						},
					}
			},
			want: "nil",
		},
		{
			name: "foreign key target arity mismatch fails",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_parent": {{"id": "parent"}},
						"fixture_child":  {{"parent_id": "parent", "extra": "value"}},
					}, map[string]erasureTableDescriptor{
						"fixture_parent": {Columns: []erasureColumn{{Name: "id", Nullable: true}}},
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "parent_id", Nullable: true}, {Name: "extra", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "FOREIGN KEY", Columns: []string{"parent_id", "extra"}, Target: "fixture_parent", TargetColumns: []string{"id"}}},
						},
					}
			},
			want: "pg:23503",
		},
		{
			name: "altered descriptor missing unique column still participates",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"present": "a"}, {"present": "b"}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "present", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"missing_runtime_column"}}},
						},
					}
			},
			want: "pg:23505",
		},
		{
			name: "fallback byte slice duplicate unique",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"payload": []byte{1, 2, 3}}, {"payload": []byte{1, 2, 3}}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "payload", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"payload"}}},
						},
					}
			},
			want: "pg:23505",
		},
		{
			name: "fallback typed nil byte slice empty byte slice nil and empty string remain distinct",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"payload": []byte(nil)}, {"payload": []byte{}}, {"payload": nil}, {"payload": ""}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "payload", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"payload"}}},
						},
					}
			},
			want: "nil",
		},
		{
			name: "fallback time value duplicate unique",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				stamp := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
				return resumeFixtureRowsByTable{
						"fixture_child": {{"created_at": stamp}, {"created_at": stamp}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "created_at", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"created_at"}}},
						},
					}
			},
			want: "pg:23505",
		},
		{
			name: "fallback float value duplicate unique",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"score": float64(1.5)}, {"score": float64(1.5)}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {
							Columns:     []erasureColumn{{Name: "score", Nullable: true}},
							Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"score"}}},
						},
					}
			},
			want: "pg:23505",
		},
		{
			name: "wider tuple falls back to deep equal",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				columns := make([]string, resumeFixtureFastTupleMax+1)
				descriptorColumns := make([]erasureColumn, len(columns))
				first := resumeFixtureRow{}
				second := resumeFixtureRow{}
				for i := range columns {
					name := "c" + string(rune('a'+i))
					columns[i] = name
					descriptorColumns[i] = erasureColumn{Name: name, Nullable: true}
					first[name] = "value"
					second[name] = "value"
				}
				return resumeFixtureRowsByTable{"fixture_child": {first, second}}, map[string]erasureTableDescriptor{
					"fixture_child": {Columns: descriptorColumns, Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: columns}}},
				}
			},
			want: "pg:23505",
		},
		{
			name: "canonical byte cap remains enforced",
			build: func() (resumeFixtureRowsByTable, map[string]erasureTableDescriptor) {
				return resumeFixtureRowsByTable{
						"fixture_child": {{"payload": make([]byte, 67108865)}},
					}, map[string]erasureTableDescriptor{
						"fixture_child": {Columns: []erasureColumn{{Name: "payload", Nullable: true}}},
					}
			},
			want: "error:external SQL fixture: canonical byte bound",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, tables := tc.build()
			reference := resumeFixtureConstraintErrorClass(resumeFixtureReferenceValidateTables(resumeFixtureConstraintTx(rows, tables)))
			optimized := resumeFixtureConstraintErrorClass(resumeFixtureConstraintTx(rows, tables).validateTables())
			if reference != optimized {
				t.Fatalf("reference=%s optimized=%s", reference, optimized)
			}
			if reference != tc.want {
				t.Fatalf("classification=%s want %s", reference, tc.want)
			}
		})
	}
}

type resumeFixtureUnexpectedString string

func TestResumeFixtureFastTupleFallbackDisjointness(t *testing.T) {
	columns := []string{"value"}
	fast := resumeFixtureRow{"value": "same"}
	if _, ok := resumeFixtureFastTuple(fast, columns); !ok {
		t.Fatal("string value should use the comparable fast tuple")
	}
	fallbackRows := []resumeFixtureRow{
		{"value": []byte("same")},
		{"value": []byte(nil)},
		{"value": time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)},
		{"value": float64(1)},
		{"value": int(1)},
		{"value": resumeFixtureUnexpectedString("same")},
	}
	for _, row := range fallbackRows {
		if _, ok := resumeFixtureFastTuple(row, columns); ok {
			t.Fatalf("unexpected fast tuple for %#v", row["value"])
		}
		if reflect.DeepEqual(resumeFixtureTuple(fast, columns), resumeFixtureTuple(row, columns)) {
			t.Fatalf("fast tuple should be disjoint from fallback value %#v", row["value"])
		}
	}

	if _, ok := resumeFixtureFastTuple(resumeFixtureRow{"value": nil}, columns); !ok {
		t.Fatal("nil should use the comparable fast tuple")
	}
	if reflect.DeepEqual(resumeFixtureTuple(resumeFixtureRow{"value": nil}, columns), resumeFixtureTuple(resumeFixtureRow{"value": []byte(nil)}, columns)) {
		t.Fatal("nil and typed nil []byte must remain distinct")
	}

	wideColumns := make([]string, resumeFixtureFastTupleMax+1)
	wideA := resumeFixtureRow{}
	wideB := resumeFixtureRow{}
	for i := range wideColumns {
		name := "w" + string(rune('a'+i))
		wideColumns[i] = name
		wideA[name] = "same"
		wideB[name] = "same"
	}
	if _, ok := resumeFixtureFastTuple(wideA, wideColumns); ok {
		t.Fatal("wide tuple should fall back to DeepEqual")
	}
	if !reflect.DeepEqual(resumeFixtureTuple(wideA, wideColumns), resumeFixtureTuple(wideB, wideColumns)) {
		t.Fatal("wide tuple fallback should preserve DeepEqual equality")
	}
	if reflect.DeepEqual(resumeFixtureTuple(fast, columns), resumeFixtureTuple(wideA, wideColumns)) {
		t.Fatal("tuple arity must distinguish fast and wide fallback values")
	}
}

func resumeFixtureConstraintTx(rows resumeFixtureRowsByTable, tables map[string]erasureTableDescriptor) *resumeFixtureTransaction {
	return &resumeFixtureTransaction{
		conn:    &resumeFixtureConnection{s: &resumeFixtureSQLService{}},
		rows:    rows,
		catalog: erasureCatalog{Tables: tables},
	}
}

func resumeFixtureConstraintErrorClass(err error) string {
	if err == nil {
		return "nil"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "pg:" + pgErr.Code
	}
	return "error:" + err.Error()
}

// resumeFixtureReferenceValidateTables is a renamed copy of the pre-optimization
// validateTables body. It is kept only as a differential oracle for synthetic
// constraint rows.
func resumeFixtureReferenceValidateTables(tx *resumeFixtureTransaction) error {
	bytesTotal := 0
	for table, rows := range tx.rows {
		d := tx.catalog.Tables[table]
		for i, r := range rows {
			for _, c := range d.Columns {
				v := r[c.Name]
				if v == nil && !c.Nullable {
					return &pgconn.PgError{Code: "23502"}
				}
				if b, ok := v.([]byte); ok {
					bytesTotal += len(b)
				}
			}
			for _, c := range d.Constraints {
				switch c.Kind {
				case "PRIMARY KEY", "UNIQUE":
					for j := 0; j < i; j++ {
						if reflect.DeepEqual(resumeFixtureTuple(rows[j], c.Columns), resumeFixtureTuple(r, c.Columns)) {
							return &pgconn.PgError{Code: "23505"}
						}
					}
				case "FOREIGN KEY":
					nullable := false
					for _, col := range c.Columns {
						if r[col] == nil {
							nullable = true
						}
					}
					if nullable {
						continue
					}
					found := false
					for _, foreign := range tx.rows[c.Target] {
						if reflect.DeepEqual(resumeFixtureTuple(r, c.Columns), resumeFixtureTuple(foreign, c.TargetColumns)) {
							found = true
							break
						}
					}
					if !found {
						return &pgconn.PgError{Code: "23503"}
					}
				case "CHECK":
					if !resumeFixtureSQLCheck(c.Expression, r) {
						return &pgconn.PgError{Code: "23514"}
					}
				}
			}
		}
	}
	if bytesTotal > 67108864 {
		return tx.conn.s.fail("canonical byte bound")
	}
	return nil
}

// Finite cross-product against the unchanged pre-optimization oracle.
func TestResumeFixtureConstraintLookupCrossProduct(t *testing.T) {
	stamp := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	values := []any{nil, "", "a", "a\x00b", "false", false, true, int64(0), int64(1), int(1), float64(1), []byte(nil), []byte{}, []byte("a"), stamp, stamp.In(time.FixedZone("UTC", 0)), resumeFixtureUnexpectedString("a"), []string{"a"}}
	for _, kind := range []string{"PRIMARY KEY", "UNIQUE", "FOREIGN KEY"} {
		for _, left := range values {
			for _, right := range values {
				rows := resumeFixtureRowsByTable{"fixture_child": {{"a": left, "b": "tail"}, {"a": right, "b": "tail"}}}
				constraint := erasureConstraint{Kind: kind, Columns: []string{"a", "b"}}
				tables := map[string]erasureTableDescriptor{"fixture_child": {Columns: []erasureColumn{{Name: "a", Nullable: true}, {Name: "b", Nullable: true}}}}
				if kind == "FOREIGN KEY" {
					rows["fixture_parent"] = []resumeFixtureRow{{"x": right, "y": "tail"}}
					rows["fixture_child"] = rows["fixture_child"][:1]
					tables["fixture_parent"] = erasureTableDescriptor{Columns: []erasureColumn{{Name: "x", Nullable: true}, {Name: "y", Nullable: true}}}
					constraint.Target, constraint.TargetColumns = "fixture_parent", []string{"x", "y"}
				}
				d := tables["fixture_child"]
				d.Constraints = []erasureConstraint{constraint}
				tables["fixture_child"] = d
				tx := resumeFixtureConstraintTx(rows, tables)
				want := resumeFixtureConstraintErrorClass(resumeFixtureReferenceValidateTables(tx))
				got := resumeFixtureConstraintErrorClass(tx.validateTables())
				if got != want {
					t.Fatalf("kind=%s left=%T right=%T got=%s want=%s", kind, left, right, got, want)
				}
			}
		}
	}
	rows := resumeFixtureRowsByTable{"fixture_child": {{"a": "one", "b": "same"}, {"a": "two", "b": "same"}}}
	tables := map[string]erasureTableDescriptor{"fixture_child": {Constraints: []erasureConstraint{{Kind: "UNIQUE", Columns: []string{"a"}}}}}
	tx := resumeFixtureConstraintTx(rows, tables)
	if err := tx.validateTables(); err != nil {
		t.Fatal(err)
	}
	d := tables["fixture_child"]
	d.Constraints[0].Columns = []string{"b"}
	tables["fixture_child"] = d
	if got := resumeFixtureConstraintErrorClass(tx.validateTables()); got != "pg:23505" {
		t.Fatal("stale constraint index", got)
	}
}
