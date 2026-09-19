package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

type resumeFixtureRow map[string]driver.Value
type resumeFixtureRowsByTable map[string][]resumeFixtureRow
type resumeFixtureTestCommitMode uint8

const (
	resumeFixtureTestNormal resumeFixtureTestCommitMode = iota
	resumeFixtureTestKnownAbort
	resumeFixtureTestPersistThenLose
	resumeFixtureTestLoseWithoutPersist
)

type resumeFixtureSQLFault struct {
	StatementID       string
	Slot              string
	Mutation          string
	Occurrence        int
	OperationLabel    string
	Err               error
	CommitMode        resumeFixtureTestCommitMode
	RollbackErr       error
	AffectedRows      *int64
	NextErr, CloseErr error
	NextAt            int
	Entered           chan struct{}
	Release           <-chan struct{}
	seen              int
}
type resumeFixtureTraceEvent struct {
	Sequence              uint64
	Graph, OperationLabel string
	TransactionID         uint64
	StatementID, Kind     string
	Arguments             []driver.Value
	Persisted, ReplyKnown bool
	Isolation             driver.IsolationLevel
	ReadOnly              bool
}
type resumeFixtureSQLSnapshot struct {
	Rows          resumeFixtureRowsByTable
	Revision      uint64
	Events        []resumeFixtureTraceEvent
	Active, Locks int
	Errors        []string
}
type resumeFixtureSQLService struct {
	mu                               sync.Mutex
	t                                *testing.T
	registry                         map[string]erasureStatement
	catalog                          erasureCatalog
	rows                             resumeFixtureRowsByTable
	revision, next                   uint64
	handles, connections, statements int
	begins                           map[string]int
	events                           []resumeFixtureTraceEvent
	failures                         []string
	active                           map[uint64]*resumeFixtureTransaction
	locks                            map[string]chan struct{}
	rowLocks                         map[string]uint64
	faults                           []*resumeFixtureSQLFault
}
type resumeFixtureContextKey struct{}

func resumeFixtureOperationContext(t *testing.T, label string) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.WithValue(context.Background(), resumeFixtureContextKey{}, label), 120*time.Second)
}
func resumeFixtureLabel(ctx context.Context) string {
	s, _ := ctx.Value(resumeFixtureContextKey{}).(string)
	return s
}
func newResumeSQLService(t *testing.T, catalog erasureCatalog) *resumeFixtureSQLService {
	t.Helper()
	s := &resumeFixtureSQLService{t: t, registry: resumeFixtureRegistry(t), catalog: catalog, begins: map[string]int{}, rows: resumeFixtureRowsByTable{}, active: map[uint64]*resumeFixtureTransaction{}, locks: map[string]chan struct{}{}, rowLocks: map[string]uint64{}}
	for _, name := range resumeFixtureTableNames {
		s.rows[name] = nil
	}
	return s
}
func (s *resumeFixtureSQLService) fail(message string) error {
	s.failures = append(s.failures, message)
	return errors.New("external SQL fixture: " + message)
}
func (s *resumeFixtureSQLService) event(tx *resumeFixtureTransaction, id, kind string, persisted, known bool) {
	if len(s.events) >= 524288 {
		s.failures = append(s.failures, "event bound exceeded")
		return
	}
	e := resumeFixtureTraceEvent{Sequence: uint64(len(s.events) + 1), StatementID: id, Kind: kind, Persisted: persisted, ReplyKnown: known}
	if tx != nil {
		e.Graph = tx.conn.graph
		e.OperationLabel = tx.label
		e.TransactionID = tx.id
		e.Isolation = tx.options.Isolation
		e.ReadOnly = tx.options.ReadOnly
	}
	s.events = append(s.events, e)
}
func resumeFixtureCopyValue(v driver.Value) driver.Value {
	if b, ok := v.([]byte); ok {
		return append([]byte(nil), b...)
	}
	return v
}
func resumeFixtureCopyRows(rows [][]driver.Value) [][]driver.Value {
	out := make([][]driver.Value, len(rows))
	for i, row := range rows {
		out[i] = make([]driver.Value, len(row))
		for j, v := range row {
			out[i][j] = resumeFixtureCopyValue(v)
		}
	}
	return out
}
func resumeFixtureCopyTables(tables resumeFixtureRowsByTable) resumeFixtureRowsByTable {
	out := resumeFixtureRowsByTable{}
	for table, rows := range tables {
		for _, row := range rows {
			r := resumeFixtureRow{}
			for c, v := range row {
				r[c] = resumeFixtureCopyValue(v)
			}
			out[table] = append(out[table], r)
		}
		if len(rows) == 0 {
			out[table] = nil
		}
	}
	return out
}
func resumeFixtureCopyCatalog(c erasureCatalog) erasureCatalog {
	out := c
	out.Rows = map[string][][]driver.Value{}
	for id, rows := range c.Rows {
		out.Rows[id] = resumeFixtureCopyRows(rows)
	}
	out.OIDs = map[string]int64{}
	for n, v := range c.OIDs {
		out.OIDs[n] = v
	}
	return out
}
func (s *resumeFixtureSQLService) Snapshot() resumeFixtureSQLSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return resumeFixtureSQLSnapshot{resumeFixtureCopyTables(s.rows), s.revision, append([]resumeFixtureTraceEvent(nil), s.events...), len(s.active), len(s.locks) + len(s.rowLocks), append([]string(nil), s.failures...)}
}
func (s *resumeFixtureSQLService) Inject(f resumeFixtureSQLFault) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Occurrence < 1 || f.Occurrence > 4096 || f.NextAt < 0 || f.NextAt > 256 {
		return s.fail("fault bound")
	}
	_, ok := s.registry[f.StatementID]
	if !ok && f.StatementID != "BEGIN" && f.StatementID != "COMMIT" && f.StatementID != "ROLLBACK" {
		return s.fail("unknown fault point")
	}
	s.faults = append(s.faults, &f)
	return nil
}
func (s *resumeFixtureSQLService) fault(ctx context.Context, id, label string) *resumeFixtureSQLFault {
	s.mu.Lock()
	var found *resumeFixtureSQLFault
	for _, f := range s.faults {
		if f.Mutation != "" {
			mutation := ""
			for _, tx := range s.active {
				if tx.ctx == ctx {
					mutation = tx.lastMutation
				}
			}
			if f.Mutation != mutation {
				continue
			}
		}
		if f.Slot != "" {
			slot := ""
			for _, tx := range s.active {
				if tx.ctx == ctx {
					slot = tx.lastEvidenceSlot
				}
			}
			if f.Slot != slot {
				continue
			}
		}
		if f.StatementID == id && (f.OperationLabel == "" || f.OperationLabel == label) {
			f.seen++
			if f.seen == f.Occurrence {
				clone := *f
				found = &clone
				break
			}
		}
	}
	s.mu.Unlock()
	if found != nil && found.Entered != nil {
		close(found.Entered)
	}
	if found != nil && found.Release != nil {
		select {
		case <-found.Release:
		case <-ctx.Done():
			found.Err = ctx.Err()
		}
	}
	return found
}
func (s *resumeFixtureSQLService) MutateCatalog(mutation func(*erasureCatalog)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.active) != 0 {
		return s.fail("catalog edit with transaction open")
	}
	mutation(&s.catalog)
	return nil
}
func resumeFixtureTuple(row resumeFixtureRow, columns []string) []driver.Value {
	out := make([]driver.Value, len(columns))
	for i, c := range columns {
		out[i] = row[c]
	}
	return out
}
func (s *resumeFixtureSQLService) CorruptExistingRow(table string, key []driver.Value, column string, replacement driver.Value) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.active) != 0 {
		return s.fail("row corruption with transaction open")
	}
	d, ok := s.catalog.Tables[table]
	if !ok {
		return s.fail("corruption table absent")
	}
	var pk []string
	validColumn := false
	for _, c := range d.Columns {
		if c.Name == column {
			validColumn = true
		}
	}
	for _, c := range d.Constraints {
		if c.Kind == "PRIMARY KEY" {
			pk = c.Columns
		}
	}
	if !validColumn {
		return s.fail("corruption column absent")
	}
	for _, r := range s.rows[table] {
		if reflect.DeepEqual(resumeFixtureTuple(r, pk), key) {
			r[column] = resumeFixtureCopyValue(replacement)
			s.event(nil, "CORRUPTION", "fault:"+s.t.Name()+":"+table+":"+column, false, false)
			s.revision++
			return nil
		}
	}
	return s.fail("corruption row absent")
}
func (s *resumeFixtureSQLService) AssertClean(t *testing.T) {
	t.Helper()
	v := s.Snapshot()
	if v.Active != 0 || v.Locks != 0 || len(v.Errors) != 0 {
		t.Fatalf("SQL service not clean: active=%d locks=%d errors=%v", v.Active, v.Locks, v.Errors)
	}
}
func (s *resumeFixtureSQLService) OpenDB(t *testing.T, graph string) *sql.DB {
	t.Helper()
	s.mu.Lock()
	s.handles++
	if s.handles > 512 {
		s.mu.Unlock()
		t.Fatal("DB handle bound")
	}
	s.mu.Unlock()
	db := sql.OpenDB(resumeFixtureConnector{s, graph})
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type resumeFixtureConnector struct {
	s     *resumeFixtureSQLService
	graph string
}

func (c resumeFixtureConnector) Driver() driver.Driver { return resumeFixtureDriver{} }
func (c resumeFixtureConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.connections >= 1024 {
		return nil, c.s.fail("connection bound")
	}
	c.s.connections++
	return &resumeFixtureConnection{s: c.s, graph: c.graph}, nil
}

type resumeFixtureDriver struct{}

func (resumeFixtureDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}

type resumeFixtureConnection struct {
	s      *resumeFixtureSQLService
	graph  string
	tx     *resumeFixtureTransaction
	closed bool
}

func (c *resumeFixtureConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements not in finite protocol")
}
func (c *resumeFixtureConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("BeginTx required")
}
func (c *resumeFixtureConnection) Close() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.s.connections--
	}
	return nil
}
func (c *resumeFixtureConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.s.mu.Lock()
	c.s.begins[resumeFixtureLabel(ctx)]++
	c.s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f := c.s.fault(ctx, "BEGIN", resumeFixtureLabel(ctx))
	if f != nil && f.Err != nil {
		return nil, f.Err
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.tx != nil && !c.tx.done {
		return nil, c.s.fail("nested transaction")
	}
	if options.Isolation != driver.IsolationLevel(sql.LevelSerializable) && options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) && options.Isolation != driver.IsolationLevel(sql.LevelReadCommitted) {
		return nil, c.s.fail("isolation")
	}
	if options.ReadOnly && options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, c.s.fail("read-only verifier isolation")
	}
	c.s.next++
	tx := &resumeFixtureTransaction{conn: c, id: c.s.next, ctx: ctx, label: resumeFixtureLabel(ctx), options: options, rows: resumeFixtureCopyTables(c.s.rows), catalog: resumeFixtureCopyCatalog(c.s.catalog), revision: c.s.revision, held: map[string]bool{}}
	c.tx = tx
	c.s.active[tx.id] = tx
	c.s.event(tx, "BEGIN", "begin", false, false)
	return tx, nil
}
func resumeFixtureNormalizeSQL(q string) string {
	var b strings.Builder
	quote := byte(0)
	space := false
	for i := 0; i < len(q); i++ {
		ch := q[i]
		if quote != 0 {
			b.WriteByte(ch)
			if ch == quote {
				if i+1 < len(q) && q[i+1] == quote {
					i++
					b.WriteByte(q[i])
				} else {
					quote = 0
				}
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			quote = ch
			b.WriteByte(ch)
			continue
		}
		if ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r' || ch == '\f' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(ch)
	}
	return b.String()
}
func (c *resumeFixtureConnection) identify(q string, args []driver.NamedValue) (string, []driver.Value, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.statements++
	if c.s.statements > 262144 || len(q) > 32768 || len(args) > 64 {
		return "", nil, c.s.fail("SQL resource bound")
	}
	normalized := resumeFixtureNormalizeSQL(q)
	for id, st := range c.s.registry {
		if st.SQL != normalized {
			continue
		}
		if len(args) != len(st.Parameters) {
			return "", nil, c.s.fail("parameter count for " + id)
		}
		values := make([]driver.Value, len(args))
		for i, a := range args {
			if a.Ordinal != i+1 || a.Name != "" {
				return "", nil, c.s.fail("nonpositional argument")
			}
			typ := strings.SplitN(st.Parameters[i], ":", 2)[1]
			nullable := strings.HasSuffix(typ, "|NULL")
			typ = strings.TrimSuffix(typ, "|NULL")
			valid := nullable && a.Value == nil
			if a.Value != nil {
				switch typ {
				case "string":
					_, valid = a.Value.(string)
				case "int64":
					_, valid = a.Value.(int64)
				case "[]byte":
					_, valid = a.Value.([]byte)
				case "time.Time":
					_, valid = a.Value.(time.Time)
				}
			}
			if !valid {
				return "", nil, c.s.fail("parameter type for " + id)
			}
			values[i] = resumeFixtureCopyValue(a.Value)
		}
		return id, values, nil
	}
	return "", nil, c.s.fail("unexpected SQL: " + normalized)
}
func (c *resumeFixtureConnection) run(ctx context.Context, q string, args []driver.NamedValue, query bool) (driver.Result, driver.Rows, error) {
	id, a, err := c.identify(q, args)
	if err != nil {
		return nil, nil, err
	}
	tx := c.tx
	if tx == nil || tx.done {
		return nil, nil, errors.New("statement outside transaction")
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	if id == "evidence_insert" {
		tx.lastEvidenceSlot = a[9].(string)
	}
	if id == "allowance_insert" || id == "allowance_spend" || id == "attempt_insert" || id == "evidence_insert" {
		tx.lastMutation = id
	}
	f := c.s.fault(ctx, id, tx.label)
	if f != nil && f.RollbackErr != nil {
		tx.rollbackErr = f.RollbackErr
	}
	if f != nil && f.Err != nil {
		return nil, nil, f.Err
	}
	if id == "artifact_lock" {
		if query {
			return nil, nil, errors.New("lock must Exec")
		}
		if err = tx.acquire(ctx, a[0].(string)); err != nil {
			return nil, nil, err
		}
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.event(tx, id, "statement", false, false)
	c.s.events[len(c.s.events)-1].Arguments = append([]driver.Value(nil), a...)
	if tx.options.Isolation == driver.IsolationLevel(sql.LevelReadCommitted) && !tx.dirty {
		tx.rows = resumeFixtureCopyTables(c.s.rows)
	}
	rows, count, err := tx.statement(id, a, query)
	if err != nil {
		return nil, nil, err
	}
	if f != nil && f.AffectedRows != nil {
		count = *f.AffectedRows
	}
	if !query {
		return driver.RowsAffected(count), nil, nil
	}
	if len(rows) > 256 {
		return nil, nil, c.s.fail("result row bound")
	}
	columns := append([]string(nil), c.s.registry[id].Columns...)
	result := &resumeFixtureDriverRows{columns: columns, rows: resumeFixtureCopyRows(rows)}
	if f != nil {
		result.nextErr = f.NextErr
		result.closeErr = f.CloseErr
		result.nextAt = f.NextAt
	}
	return nil, result, nil
}
func (c *resumeFixtureConnection) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	r, _, e := c.run(ctx, q, a, false)
	return r, e
}
func (c *resumeFixtureConnection) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	_, r, e := c.run(ctx, q, a, true)
	return r, e
}

type resumeFixtureDriverRows struct {
	columns           []string
	rows              [][]driver.Value
	at, nextAt        int
	nextErr, closeErr error
	closed            bool
}

func (r *resumeFixtureDriverRows) Columns() []string { return r.columns }
func (r *resumeFixtureDriverRows) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.closeErr
}
func (r *resumeFixtureDriverRows) Next(dst []driver.Value) error {
	if r.nextErr != nil && r.at == r.nextAt {
		return r.nextErr
	}
	if r.at == len(r.rows) {
		return io.EOF
	}
	if len(dst) != len(r.rows[r.at]) {
		return errors.New("external SQL projection mismatch")
	}
	copy(dst, r.rows[r.at])
	r.at++
	return nil
}

type resumeFixtureTransaction struct {
	conn             *resumeFixtureConnection
	id               uint64
	ctx              context.Context
	label            string
	options          driver.TxOptions
	rows             resumeFixtureRowsByTable
	catalog          erasureCatalog
	revision         uint64
	tenant           string
	held             map[string]bool
	dirty, done      bool
	rollbackErr      error
	lastEvidenceSlot string
	lastMutation     string
}

func (tx *resumeFixtureTransaction) acquire(ctx context.Context, key string) error {
	s := tx.conn.s
	if tx.tenant == "" || tx.options.Isolation != driver.IsolationLevel(sql.LevelSerializable) || tx.options.ReadOnly {
		return errors.New("invalid common lock phase")
	}
	for {
		s.mu.Lock()
		if tx.held[key] {
			s.mu.Unlock()
			return nil
		}
		wait, exists := s.locks[key]
		if !exists {
			if tx.revision != s.revision {
				s.mu.Unlock()
				return &pgconn.PgError{Code: "40001"}
			}
			s.locks[key] = make(chan struct{})
			tx.held[key] = true
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (tx *resumeFixtureTransaction) finish() {
	s := tx.conn.s
	tx.done = true
	tx.tenant = ""
	for key := range tx.held {
		close(s.locks[key])
		delete(s.locks, key)
	}
	for key, owner := range s.rowLocks {
		if owner == tx.id {
			delete(s.rowLocks, key)
		}
	}
	delete(s.active, tx.id)
}
func (tx *resumeFixtureTransaction) Commit() error {
	s := tx.conn.s
	f := s.fault(tx.ctx, "COMMIT", tx.label)
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done {
		return sql.ErrTxDone
	}
	if f != nil && (f.CommitMode == resumeFixtureTestKnownAbort || f.CommitMode == resumeFixtureTestLoseWithoutPersist) {
		tx.finish()
		s.event(tx, "COMMIT", "no-persistence", false, false)
		return f.Err
	}
	if tx.dirty && tx.revision != s.revision {
		tx.finish()
		return &pgconn.PgError{Code: "40001"}
	}
	if f != nil && f.Err != nil && f.CommitMode != resumeFixtureTestPersistThenLose {
		tx.finish()
		s.event(tx, "COMMIT", "no-persistence", false, false)
		return f.Err
	}
	if tx.dirty {
		if err := tx.validateTables(); err != nil {
			tx.finish()
			return err
		}
		s.rows = resumeFixtureCopyTables(tx.rows)
		s.revision++
	}
	persisted := tx.dirty
	s.event(tx, "COMMIT", "durable", persisted, false)
	tx.finish()
	if f != nil && f.CommitMode == resumeFixtureTestPersistThenLose {
		return f.Err
	}
	s.event(tx, "COMMIT", "reply", persisted, true)
	return nil
}
func (tx *resumeFixtureTransaction) Rollback() error {
	s := tx.conn.s
	f := s.fault(tx.ctx, "ROLLBACK", tx.label)
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done {
		return sql.ErrTxDone
	}
	tx.finish()
	s.event(tx, "ROLLBACK", "rollback", false, false)
	if f != nil && f.Err != nil {
		return f.Err
	}
	return tx.rollbackErr
}
func (tx *resumeFixtureTransaction) lookup(table string, columns []string, values []driver.Value) []resumeFixtureRow {
	var out []resumeFixtureRow
	for _, r := range tx.rows[table] {
		if r["tenant_id"] != tx.tenant {
			continue
		}
		if reflect.DeepEqual(resumeFixtureTuple(r, columns), values) {
			out = append(out, r)
		}
	}
	return out
}
func resumeFixtureProject(row resumeFixtureRow, names []string) []driver.Value {
	out := make([]driver.Value, len(names))
	for i, n := range names {
		out[i] = resumeFixtureCopyValue(row[n])
	}
	return out
}
func resumeFixtureNames(columns []string) []string {
	out := make([]string, len(columns))
	for i, c := range columns {
		out[i] = strings.SplitN(c, ":", 2)[0]
	}
	return out
}
func (tx *resumeFixtureTransaction) statement(id string, a []driver.Value, query bool) ([][]driver.Value, int64, error) {
	s := tx.conn.s
	cat := id == "role" || id == "authority_schemas" || id == "authority_identity" || id == "migration_rows" || id == "relation" || id == "attributes" || id == "constraints" || id == "indexes" || id == "policies" || id == "table_privileges" || id == "confirmation_privileges" || id == "allowance_counter_privileges" || id == "allowance_immutable_privileges" || id == "user_triggers"
	if cat {
		if !query || !tx.options.ReadOnly || tx.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || tx.tenant != "" {
			return nil, 0, s.fail("catalog transaction shape")
		}
		k := id
		if id == "relation" {
			if a[0] != tx.catalog.Schema {
				return nil, 0, nil
			}
			oid, ok := tx.catalog.OIDs[a[1].(string)]
			if !ok {
				return nil, 0, s.fail("unregistered relation")
			}
			k = erasureCatalogKey(id, oid)
		} else if len(a) > 0 {
			oid := a[0].(int64)
			if id == "table_privileges" && (a[1] != tx.catalog.Role || a[2] != tx.catalog.Schema) {
				return nil, 0, s.fail("privilege binding")
			}
			if (id == "confirmation_privileges" || id == "allowance_counter_privileges" || id == "allowance_immutable_privileges") && a[1] != tx.catalog.Role {
				return nil, 0, s.fail("column privilege binding")
			}
			k = erasureCatalogKey(id, oid)
		}
		if id == "user_triggers" {
			if override, ok := tx.catalog.Rows[k]; ok {
				return override, 0, nil
			}
			for _, trigger := range tx.catalog.Rows["trigger_inventory"] {
				if trigger[0] == a[0] && trigger[1] == false {
					return [][]driver.Value{{true}}, 0, nil
				}
			}
			return [][]driver.Value{{false}}, 0, nil
		}
		return tx.catalog.Rows[k], 0, nil
	}
	if id == "tenant_guc" {
		if query || tx.options.ReadOnly || tx.tenant != "" {
			return nil, 0, s.fail("GUC order")
		}
		tx.tenant = a[0].(string)
		return nil, 1, nil
	}
	if tx.tenant == "" || tx.options.ReadOnly {
		return nil, 0, s.fail("scoped statement without tenant")
	}
	if id == "artifact_lock" {
		return nil, 1, nil
	}
	if len(a) > 0 && a[0] != tx.tenant {
		return nil, 0, s.fail("tenant predicate mismatch")
	}
	if _, ok := resumeScopedStatements[id]; ok {
		return tx.resumeStatement(id, a, query)
	}
	readTables := map[string][]string{"scope_read": {erasureScopes}, "metadata_read": {erasureMetadata}, "key_occupancy": {erasureAdmissions}, "legacy_lineage": {"open_trestle_artifact_deletion_authorizations", "open_trestle_artifact_deletion_receipts"}, "admission_read": {erasureAdmissions, erasureScopes, erasureMetadata}, "admission_lock_read": {erasureAdmissions, erasureScopes, erasureMetadata}, "operation_presence": {erasureOperations}, "operation_read": {erasureOperations, erasureAdmissions, erasureScopes, erasureMetadata}, "operation_ref_read": {erasureOperations, erasureAdmissions, erasureScopes, erasureMetadata}}
	for _, table := range readTables[id] {
		p := tx.catalog.Rows[erasureCatalogKey("table_privileges", tx.catalog.OIDs[table])]
		if len(p) != 1 || p[0][0] != true || p[0][1] != true {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
	}
	if table := map[string]string{"scope_insert": erasureScopes, "metadata_insert": erasureMetadata, "admission_insert": erasureAdmissions, "operation_insert": erasureOperations}[id]; table != "" {
		p := tx.catalog.Rows[erasureCatalogKey("table_privileges", tx.catalog.OIDs[table])]
		if len(p) != 1 || p[0][0] != true || p[0][2] != true {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
	}
	if id == "confirmation_cas" {
		p := tx.catalog.Rows[erasureCatalogKey("confirmation_privileges", tx.catalog.OIDs[erasureAdmissions])]
		if len(p) != 1 || p[0][0] != true || p[0][1] != true || p[0][2] != true {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
	}
	if (id == "admission_read" || id == "operation_read") && len(tx.held) == 0 && tx.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, 0, s.fail("canonical read requires repeatable snapshot")
	}
	mutation := id == "scope_insert" || id == "metadata_insert" || id == "admission_insert" || id == "operation_insert" || id == "confirmation_cas"
	if mutation || id == "admission_lock_read" {
		if tx.options.Isolation != driver.IsolationLevel(sql.LevelSerializable) || len(tx.held) != 1 || query == mutation {
			return nil, 0, s.fail("mutation isolation/lock/method")
		}
	}
	if !mutation && !query {
		return nil, 0, s.fail("query invoked as Exec")
	}
	tru := []string{"tenant_id", "repository_id", "review_run_id"}
	key := append(append([]string(nil), tru...), "artifact_identity")
	scoped := append(append([]string(nil), tru...), "namespace_identity", "artifact_identity")
	switch id {
	case "scope_insert", "metadata_insert", "admission_insert", "operation_insert":
		table := map[string]string{"scope_insert": erasureScopes, "metadata_insert": erasureMetadata, "admission_insert": erasureAdmissions, "operation_insert": erasureOperations}[id]
		r := resumeFixtureRow{}
		for i, p := range s.registry[id].Parameters {
			r[strings.SplitN(p, ":", 2)[0]] = resumeFixtureCopyValue(a[i])
		}
		for _, c := range tx.catalog.Tables[table].Columns {
			if _, ok := r[c.Name]; !ok {
				if c.Default != nil {
					r[c.Name] = time.Now().UTC().Truncate(time.Millisecond)
				} else {
					r[c.Name] = nil
				}
			}
		}
		if id == "scope_insert" {
			for _, old := range tx.rows[table] {
				for _, c := range tx.catalog.Tables[table].Constraints {
					if (c.Kind == "PRIMARY KEY" || c.Kind == "UNIQUE") && reflect.DeepEqual(resumeFixtureTuple(old, c.Columns), resumeFixtureTuple(r, c.Columns)) {
						return nil, 0, nil
					}
				}
			}
		}
		if table != erasureScopes {
			wanted := "artifact:" + r["scope_identity"].(string) + ":" + r["artifact_identity"].(string)
			if !tx.held[wanted] {
				return nil, 0, s.fail("wrong artifact advisory key")
			}
		}
		if len(tx.rows[table]) >= 8192 {
			return nil, 0, s.fail("row bound")
		}
		tx.rows[table] = append(tx.rows[table], r)
		if err := tx.validateTables(); err != nil {
			tx.rows[table] = tx.rows[table][:len(tx.rows[table])-1]
			return nil, 0, err
		}
		tx.dirty = true
		return nil, 1, nil
	case "scope_read":
		rows := tx.lookup(erasureScopes, tru, a)
		out := [][]driver.Value{}
		for _, r := range rows {
			out = append(out, []driver.Value{r["scope_identity"]})
		}
		return out, 0, nil
	case "metadata_read":
		out := [][]driver.Value{}
		for _, r := range tx.lookup(erasureMetadata, key, a) {
			out = append(out, resumeFixtureProject(r, resumeFixtureNames(s.registry[id].Columns)))
		}
		return out, 0, nil
	case "key_occupancy":
		out := [][]driver.Value{}
		for _, r := range tx.lookup(erasureAdmissions, key, a) {
			out = append(out, []driver.Value{r["namespace_identity"], r["admission_identity"]})
		}
		return out, 0, nil
	case "legacy_lineage":
		return [][]driver.Value{{len(tx.lookup("open_trestle_artifact_deletion_authorizations", key, a)) > 0, len(tx.lookup("open_trestle_artifact_deletion_receipts", key, a)) > 0}}, 0, nil
	case "admission_read", "admission_lock_read":
		out := [][]driver.Value{}
		for _, r := range tx.lookup(erasureAdmissions, scoped, a) {
			if id == "admission_lock_read" {
				wanted := "artifact:" + r["scope_identity"].(string) + ":" + r["artifact_identity"].(string)
				if !tx.held[wanted] {
					return nil, 0, s.fail("wrong common artifact lock")
				}
				rowKey := "row:" + wanted
				if owner := s.rowLocks[rowKey]; owner != 0 && owner != tx.id {
					return nil, 0, &pgconn.PgError{Code: "40001"}
				}
				s.rowLocks[rowKey] = tx.id
			}
			out = append(out, tx.joinAdmission(r))
		}
		return out, 0, nil
	case "operation_presence":
		out := [][]driver.Value{}
		for _, r := range tx.lookup(erasureOperations, scoped, a) {
			out = append(out, []driver.Value{r["operation_identity"]})
		}
		return out, 0, nil
	case "operation_read", "operation_ref_read":
		cols := scoped
		if id == "operation_ref_read" {
			cols = append(append([]string(nil), tru...), "namespace_identity", "operation_identity")
		}
		out := [][]driver.Value{}
		for _, r := range tx.lookup(erasureOperations, cols, a) {
			values := resumeFixtureProject(r, resumeFixtureNames(s.registry["operation_insert"].Parameters))
			ac := []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}
			admitted := tx.lookup(erasureAdmissions, ac, resumeFixtureTuple(r, ac))
			var ar resumeFixtureRow
			if len(admitted) > 0 {
				ar = admitted[0]
			}
			values = append(values, tx.joinAdmission(ar)...)
			out = append(out, values)
		}
		return out, 0, nil
	case "confirmation_cas":
		cols := []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}
		rows := tx.lookup(erasureAdmissions, cols, a[:7])
		count := int64(0)
		for _, r := range rows {
			if r["confirmed_version"] != nil || r["confirmed_ciphertext_digest"] != nil || r["confirmed_at_milliseconds"] != nil {
				continue
			}
			if len(tx.lookup(erasureOperations, scoped, resumeFixtureTuple(r, scoped))) != 0 {
				continue
			}
			r["confirmed_version"], r["confirmed_ciphertext_digest"], r["confirmed_at_milliseconds"] = a[7], a[8], a[9]
			count++
		}
		if count > 0 {
			if err := tx.validateTables(); err != nil {
				return nil, 0, err
			}
			tx.dirty = true
		}
		return nil, count, nil
	}
	return nil, 0, s.fail("unimplemented registered SQL")
}
func (tx *resumeFixtureTransaction) joinAdmission(r resumeFixtureRow) []driver.Value {
	var names []string
	for _, c := range tx.catalog.Tables[erasureAdmissions].Columns {
		names = append(names, c.Name)
	}
	out := resumeFixtureProject(r, names)
	var scope, meta resumeFixtureRow
	if r != nil {
		sc := []string{"tenant_id", "repository_id", "review_run_id"}
		m := append(append([]string(nil), sc...), "artifact_identity")
		if found := tx.lookup(erasureScopes, sc, resumeFixtureTuple(r, sc)); len(found) > 0 {
			scope = found[0]
		}
		if found := tx.lookup(erasureMetadata, m, resumeFixtureTuple(r, m)); len(found) > 0 {
			meta = found[0]
		}
	}
	out = append(out, scope["scope_identity"])
	out = append(out, resumeFixtureProject(meta, []string{"scope_identity", "artifact_identity", "payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"})...)
	return out
}

const resumeFixtureFastTupleMax = 16

type resumeFixtureConstraintLookupKey struct {
	Table string
	Index int
}

type resumeFixtureComparableValue struct {
	Kind uint8
	Text string
	Int  int64
	Bool bool
}

type resumeFixtureComparableTuple struct {
	Length uint8
	Values [resumeFixtureFastTupleMax]resumeFixtureComparableValue
}

type resumeFixtureUniqueConstraintLookup struct {
	Seen map[resumeFixtureComparableTuple]struct{}
}

type resumeFixtureForeignConstraintLookup struct {
	Built bool
	Fast  bool
	Seen  map[resumeFixtureComparableTuple]struct{}
}

func resumeFixtureFastTuple(row resumeFixtureRow, columns []string) (resumeFixtureComparableTuple, bool) {
	if len(columns) > resumeFixtureFastTupleMax {
		return resumeFixtureComparableTuple{}, false
	}
	var out resumeFixtureComparableTuple
	out.Length = uint8(len(columns))
	for i, col := range columns {
		switch v := row[col].(type) {
		case nil:
			out.Values[i].Kind = 1
		case string:
			out.Values[i].Kind = 2
			out.Values[i].Text = v
		case int64:
			out.Values[i].Kind = 3
			out.Values[i].Int = v
		case bool:
			out.Values[i].Kind = 4
			out.Values[i].Bool = v
		default:
			return resumeFixtureComparableTuple{}, false
		}
	}
	return out, true
}

func resumeFixtureBuildForeignConstraintLookup(rows []resumeFixtureRow, columns []string) resumeFixtureForeignConstraintLookup {
	out := resumeFixtureForeignConstraintLookup{Built: true, Fast: true, Seen: map[resumeFixtureComparableTuple]struct{}{}}
	for _, row := range rows {
		key, ok := resumeFixtureFastTuple(row, columns)
		if !ok {
			return resumeFixtureForeignConstraintLookup{Built: true}
		}
		out.Seen[key] = struct{}{}
	}
	return out
}

func (tx *resumeFixtureTransaction) validateTables() error {
	bytesTotal := 0
	uniqueLookups := map[resumeFixtureConstraintLookupKey]*resumeFixtureUniqueConstraintLookup{}
	foreignLookups := map[resumeFixtureConstraintLookupKey]resumeFixtureForeignConstraintLookup{}
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
			for constraintIndex, c := range d.Constraints {
				switch c.Kind {
				case "PRIMARY KEY", "UNIQUE":
					lookupKey := resumeFixtureConstraintLookupKey{Table: table, Index: constraintIndex}
					lookup := uniqueLookups[lookupKey]
					if lookup == nil {
						lookup = &resumeFixtureUniqueConstraintLookup{Seen: map[resumeFixtureComparableTuple]struct{}{}}
						uniqueLookups[lookupKey] = lookup
					}
					key, ok := resumeFixtureFastTuple(r, c.Columns)
					if ok {
						if _, found := lookup.Seen[key]; found {
							return &pgconn.PgError{Code: "23505"}
						}
						lookup.Seen[key] = struct{}{}
						continue
					}
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
					key, ok := resumeFixtureFastTuple(r, c.Columns)
					if ok {
						lookupKey := resumeFixtureConstraintLookupKey{Table: table, Index: constraintIndex}
						lookup, built := foreignLookups[lookupKey]
						if !built {
							lookup = resumeFixtureBuildForeignConstraintLookup(tx.rows[c.Target], c.TargetColumns)
							foreignLookups[lookupKey] = lookup
						}
						if lookup.Fast {
							if _, found := lookup.Seen[key]; found {
								continue
							}
							return &pgconn.PgError{Code: "23503"}
						}
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
func resumeFixtureSQLText(r resumeFixtureRow, c string) string { v, _ := r[c].(string); return v }
func resumeFixtureSQLInt(r resumeFixtureRow, c string) int64   { v, _ := r[c].(int64); return v }
func resumeFixtureSQLBytes(r resumeFixtureRow, c string) int {
	switch v := r[c].(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	}
	return 0
}

type resumeHexPredicate struct{}

var resumeFixtureSQLHex resumeHexPredicate

func (resumeHexPredicate) MatchString(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func resumeFixtureSQLCheck(expression string, r resumeFixtureRow) bool {
	switch expression {
	case "octet_length(tenant_id) BETWEEN 1 AND 128":
		if r["tenant_id"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "tenant_id")
		return n >= 1 && n <= 128
	case "octet_length(repository_id) BETWEEN 1 AND 128":
		if r["repository_id"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "repository_id")
		return n >= 1 && n <= 128
	case "octet_length(review_run_id) BETWEEN 1 AND 128":
		if r["review_run_id"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "review_run_id")
		return n >= 1 && n <= 128
	case "scope_identity ~ '^[0-9a-f]{64}$'":
		if r["scope_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "scope_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "artifact_identity ~ '^[0-9a-f]{64}$'":
		if r["artifact_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "artifact_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "payload_digest ~ '^[0-9a-f]{64}$'":
		if r["payload_digest"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "payload_digest")
		return resumeFixtureSQLHex.MatchString(v)
	case "kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result')":
		if r["kind"] == nil {
			return true
		}
		switch resumeFixtureSQLText(r, "kind") {
		case "source_snapshot", "change_model", "deterministic_evidence", "retrieval_result", "context_packet", "candidate_batch", "verification_batch", "verified_finding_set", "publication_plan", "run_export", "task_input", "webhook_delivery", "source_file", "publication_receipt", "investigation_turn", "investigation_tool_result":
			return true
		}
		return false
	case "classification IN ('public', 'internal', 'confidential', 'restricted')":
		if r["classification"] == nil {
			return true
		}
		switch resumeFixtureSQLText(r, "classification") {
		case "public", "internal", "confidential", "restricted":
			return true
		}
		return false
	case "origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy', 'memory')":
		if r["origin"] == nil {
			return true
		}
		switch resumeFixtureSQLText(r, "origin") {
		case "host", "repository", "deterministic_tool", "model", "independent_verifier", "policy", "memory":
			return true
		}
		return false
	case "protection IN ('process_private', 'envelope_encrypted')":
		if r["protection"] == nil {
			return true
		}
		switch resumeFixtureSQLText(r, "protection") {
		case "process_private", "envelope_encrypted":
			return true
		}
		return false
	case "expires_at > created_at":
		a, ok := r["expires_at"].(time.Time)
		b, other := r["created_at"].(time.Time)
		return ok && other && a.After(b)
	case "authorization_identity ~ '^[0-9a-f]{64}$'":
		if r["authorization_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "authorization_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "policy_identity ~ '^[0-9a-f]{64}$'":
		if r["policy_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "policy_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "hold_clearance_identity ~ '^[0-9a-f]{64}$'":
		if r["hold_clearance_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "hold_clearance_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "octet_length(principal_identity) BETWEEN 1 AND 128":
		if r["principal_identity"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "principal_identity")
		return n >= 1 && n <= 128
	case "reason IN ('expired', 'tenant_erasure', 'repository_erasure')":
		if r["reason"] == nil {
			return true
		}
		switch resumeFixtureSQLText(r, "reason") {
		case "expired", "tenant_erasure", "repository_erasure":
			return true
		}
		return false
	case "expires_at > issued_at":
		a, ok := r["expires_at"].(time.Time)
		b, other := r["issued_at"].(time.Time)
		return ok && other && a.After(b)
	case "receipt_identity ~ '^[0-9a-f]{64}$'":
		if r["receipt_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "receipt_identity")
		return resumeFixtureSQLHex.MatchString(v)
	case "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["scope_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "scope_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["namespace_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "namespace_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["artifact_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "artifact_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["admission_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "admission_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["database_authority_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "database_authority_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["admitted_policy_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "admitted_policy_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_admission) BETWEEN 1 AND 16384":
		if r["canonical_admission"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "canonical_admission")
		return n >= 1 && n <= 16384
	case "octet_length(canonical_namespace) BETWEEN 1 AND 4096":
		if r["canonical_namespace"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "canonical_namespace")
		return n >= 1 && n <= 4096
	case "octet_length(admitted_policy) BETWEEN 1 AND 16384":
		if r["admitted_policy"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "admitted_policy")
		return n >= 1 && n <= 16384
	case "admitted_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["admitted_at_milliseconds"] == nil {
			return true
		}
		v := resumeFixtureSQLInt(r, "admitted_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "(confirmed_version IS NULL AND confirmed_ciphertext_digest IS NULL AND confirmed_at_milliseconds IS NULL) OR (confirmed_version IS NOT NULL AND confirmed_ciphertext_digest IS NOT NULL AND confirmed_at_milliseconds IS NOT NULL AND left(confirmed_version, 8) = 'version:' AND octet_length(confirmed_version) BETWEEN 9 AND 512 AND confirmed_version <> 'version:null' AND confirmed_version !~ '[[:space:][:cntrl:]]' AND confirmed_ciphertext_digest ~ '^[0-9a-f]{64}$' AND confirmed_ciphertext_digest <> '0000000000000000000000000000000000000000000000000000000000000000' AND confirmed_at_milliseconds BETWEEN 1 AND 253402300799999 AND confirmed_at_milliseconds >= admitted_at_milliseconds)":
		n := 0
		for _, c := range []string{"confirmed_version", "confirmed_ciphertext_digest", "confirmed_at_milliseconds"} {
			if r[c] != nil {
				n++
			}
		}
		if n == 0 {
			return true
		}
		if n != 3 {
			return false
		}
		v := resumeFixtureSQLText(r, "confirmed_version")
		d := resumeFixtureSQLText(r, "confirmed_ciphertext_digest")
		at := resumeFixtureSQLInt(r, "confirmed_at_milliseconds")
		return strings.HasPrefix(v, "version:") && len(v) >= 9 && len(v) <= 512 && v != "version:null" && utf8.ValidString(v) && strings.IndexFunc(v, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) < 0 && resumeFixtureSQLHex.MatchString(d) && d != strings.Repeat("0", 64) && at >= 1 && at <= 253402300799999 && at >= resumeFixtureSQLInt(r, "admitted_at_milliseconds")
	case "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["operation_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "operation_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["authorization_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "authorization_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["authorization_document_digest"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "authorization_document_digest")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["protected_policy_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "protected_policy_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_operation) BETWEEN 1 AND 16384":
		if r["canonical_operation"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "canonical_operation")
		return n >= 1 && n <= 16384
	case "octet_length(canonical_authorization) BETWEEN 1 AND 8192":
		if r["canonical_authorization"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "canonical_authorization")
		return n >= 1 && n <= 8192
	case "octet_length(accepted_policy) BETWEEN 1 AND 16384":
		if r["accepted_policy"] == nil {
			return true
		}
		n := resumeFixtureSQLBytes(r, "accepted_policy")
		return n >= 1 && n <= 16384
	case "prepared_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["prepared_at_milliseconds"] == nil {
			return true
		}
		v := resumeFixtureSQLInt(r, "prepared_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "accepted_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["accepted_at_milliseconds"] == nil {
			return true
		}
		v := resumeFixtureSQLInt(r, "accepted_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "accepted_at_milliseconds >= prepared_at_milliseconds":
		return resumeFixtureSQLInt(r, "accepted_at_milliseconds") >= resumeFixtureSQLInt(r, "prepared_at_milliseconds")

	case "evidence_identity ~ '^[0-9a-f]{64}$' AND evidence_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "evidence_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(slot) BETWEEN 1 AND 80":
		n := resumeFixtureSQLBytes(r, "slot")
		return n >= 1 && n <= 80
	case "kind IN ('response', 'unknown', 'fence', 'verification', 'candidate', 'published')":
		v := resumeFixtureSQLText(r, "kind")
		return v == "response" || v == "unknown" || v == "fence" || v == "verification" || v == "candidate" || v == "published"
	case "attempt_identity IS NULL OR (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000')":
		if r["attempt_identity"] == nil {
			return true
		}
		v := resumeFixtureSQLText(r, "attempt_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_evidence) BETWEEN 1 AND 1048576":
		n := resumeFixtureSQLBytes(r, "canonical_evidence")
		return n >= 1 && n <= 1048576
	case "observed_at_milliseconds BETWEEN 1 AND 253402300799999":
		v := resumeFixtureSQLInt(r, "observed_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "(kind = 'response' AND attempt_identity IS NOT NULL AND slot = 'response:' || attempt_identity) OR (kind = 'unknown' AND attempt_identity IS NOT NULL AND slot = 'unknown:' || attempt_identity) OR (kind = 'fence' AND attempt_identity IS NULL AND slot = 'fence') OR (kind = 'verification' AND attempt_identity IS NULL AND slot ~ '^verification:[0-9a-f]{64}$') OR (kind = 'candidate' AND attempt_identity IS NULL AND slot = 'candidate') OR (kind = 'published' AND attempt_identity IS NULL AND slot = 'published')":
		kind, slot := resumeFixtureSQLText(r, "kind"), resumeFixtureSQLText(r, "slot")
		a := r["attempt_identity"]
		switch kind {
		case "response", "unknown":
			return a != nil && slot == kind+":"+resumeFixtureSQLText(r, "attempt_identity")
		case "fence", "candidate", "published":
			return a == nil && slot == kind
		case "verification":
			return a == nil && strings.HasPrefix(slot, "verification:") && resumeFixtureSQLHex.MatchString(strings.TrimPrefix(slot, "verification:"))
		}
		return false
	case "allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "allowance_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "reservation_identity ~ '^[0-9a-f]{64}$' AND reservation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "reservation_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "attempt_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "request_identity ~ '^[0-9a-f]{64}$' AND request_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "request_identity")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_request) BETWEEN 1 AND 8192":
		n := resumeFixtureSQLBytes(r, "canonical_request")
		return n >= 1 && n <= 8192
	case "octet_length(canonical_attempt) BETWEEN 1 AND 1024":
		n := resumeFixtureSQLBytes(r, "canonical_attempt")
		return n >= 1 && n <= 1024
	case "sequence BETWEEN 1 AND 4096":
		v := resumeFixtureSQLInt(r, "sequence")
		return v >= 1 && v <= 4096
	case "reserved_at_milliseconds BETWEEN 1 AND 253402300799999":
		v := resumeFixtureSQLInt(r, "reserved_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "cost_requests BETWEEN 0 AND 4096":
		v := resumeFixtureSQLInt(r, "cost_requests")
		return v >= 0 && v <= 4096
	case "cost_mutations BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "cost_mutations")
		return v >= 0 && v <= 2048
	case "cost_reads BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "cost_reads")
		return v >= 0 && v <= 2048
	case "cost_lists BETWEEN 0 AND 1024":
		v := resumeFixtureSQLInt(r, "cost_lists")
		return v >= 0 && v <= 1024
	case "cost_creates BETWEEN 0 AND 128":
		v := resumeFixtureSQLInt(r, "cost_creates")
		return v >= 0 && v <= 128
	case "cost_deletes BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "cost_deletes")
		return v >= 0 && v <= 2048
	case "cost_pages BETWEEN 0 AND 1024":
		v := resumeFixtureSQLInt(r, "cost_pages")
		return v >= 0 && v <= 1024
	case "cost_versions BETWEEN 0 AND 262144":
		v := resumeFixtureSQLInt(r, "cost_versions")
		return v >= 0 && v <= 262144
	case "cost_response_bytes BETWEEN 0 AND 1073741824":
		v := resumeFixtureSQLInt(r, "cost_response_bytes")
		return v >= 0 && v <= 1073741824
	case "cost_list_bytes BETWEEN 0 AND 67108864":
		v := resumeFixtureSQLInt(r, "cost_list_bytes")
		return v >= 0 && v <= 67108864
	case "cost_write_bytes BETWEEN 0 AND 2097152":
		v := resumeFixtureSQLInt(r, "cost_write_bytes")
		return v >= 0 && v <= 2097152
	case "cost_requests = 1":
		return resumeFixtureSQLInt(r, "cost_requests") == 1
	case "cost_mutations = cost_creates + cost_deletes":
		return resumeFixtureSQLInt(r, "cost_mutations") == resumeFixtureSQLInt(r, "cost_creates")+resumeFixtureSQLInt(r, "cost_deletes")
	case "cost_reads + cost_lists + cost_creates + cost_deletes = 1":
		return resumeFixtureSQLInt(r, "cost_reads")+resumeFixtureSQLInt(r, "cost_lists")+resumeFixtureSQLInt(r, "cost_creates")+resumeFixtureSQLInt(r, "cost_deletes") == 1
	case "cost_pages = cost_lists":
		return resumeFixtureSQLInt(r, "cost_pages") == resumeFixtureSQLInt(r, "cost_lists")
	case "cost_mutations BETWEEN 0 AND 1":
		v := resumeFixtureSQLInt(r, "cost_mutations")
		return v >= 0 && v <= 1
	case "octet_length(canonical_allowance) BETWEEN 1 AND 4096":
		n := resumeFixtureSQLBytes(r, "canonical_allowance")
		return n >= 1 && n <= 4096
	case "allowance_document_digest ~ '^[0-9a-f]{64}$' AND allowance_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'":
		v := resumeFixtureSQLText(r, "allowance_document_digest")
		return resumeFixtureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "maximum_requests BETWEEN 0 AND 4096":
		v := resumeFixtureSQLInt(r, "maximum_requests")
		return v >= 0 && v <= 4096
	case "maximum_mutations BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "maximum_mutations")
		return v >= 0 && v <= 2048
	case "maximum_reads BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "maximum_reads")
		return v >= 0 && v <= 2048
	case "maximum_lists BETWEEN 0 AND 1024":
		v := resumeFixtureSQLInt(r, "maximum_lists")
		return v >= 0 && v <= 1024
	case "maximum_creates BETWEEN 0 AND 128":
		v := resumeFixtureSQLInt(r, "maximum_creates")
		return v >= 0 && v <= 128
	case "maximum_deletes BETWEEN 0 AND 2048":
		v := resumeFixtureSQLInt(r, "maximum_deletes")
		return v >= 0 && v <= 2048
	case "maximum_pages BETWEEN 0 AND 1024":
		v := resumeFixtureSQLInt(r, "maximum_pages")
		return v >= 0 && v <= 1024
	case "maximum_versions BETWEEN 0 AND 262144":
		v := resumeFixtureSQLInt(r, "maximum_versions")
		return v >= 0 && v <= 262144
	case "maximum_response_bytes BETWEEN 0 AND 1073741824":
		v := resumeFixtureSQLInt(r, "maximum_response_bytes")
		return v >= 0 && v <= 1073741824
	case "maximum_list_bytes BETWEEN 0 AND 67108864":
		v := resumeFixtureSQLInt(r, "maximum_list_bytes")
		return v >= 0 && v <= 67108864
	case "maximum_write_bytes BETWEEN 0 AND 2097152":
		v := resumeFixtureSQLInt(r, "maximum_write_bytes")
		return v >= 0 && v <= 2097152
	case "spent_requests BETWEEN 0 AND maximum_requests":
		v := resumeFixtureSQLInt(r, "spent_requests")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_requests")
	case "spent_mutations BETWEEN 0 AND maximum_mutations":
		v := resumeFixtureSQLInt(r, "spent_mutations")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_mutations")
	case "spent_reads BETWEEN 0 AND maximum_reads":
		v := resumeFixtureSQLInt(r, "spent_reads")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_reads")
	case "spent_lists BETWEEN 0 AND maximum_lists":
		v := resumeFixtureSQLInt(r, "spent_lists")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_lists")
	case "spent_creates BETWEEN 0 AND maximum_creates":
		v := resumeFixtureSQLInt(r, "spent_creates")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_creates")
	case "spent_deletes BETWEEN 0 AND maximum_deletes":
		v := resumeFixtureSQLInt(r, "spent_deletes")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_deletes")
	case "spent_pages BETWEEN 0 AND maximum_pages":
		v := resumeFixtureSQLInt(r, "spent_pages")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_pages")
	case "spent_versions BETWEEN 0 AND maximum_versions":
		v := resumeFixtureSQLInt(r, "spent_versions")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_versions")
	case "spent_response_bytes BETWEEN 0 AND maximum_response_bytes":
		v := resumeFixtureSQLInt(r, "spent_response_bytes")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_response_bytes")
	case "spent_list_bytes BETWEEN 0 AND maximum_list_bytes":
		v := resumeFixtureSQLInt(r, "spent_list_bytes")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_list_bytes")
	case "spent_write_bytes BETWEEN 0 AND maximum_write_bytes":
		v := resumeFixtureSQLInt(r, "spent_write_bytes")
		return v >= 0 && v <= resumeFixtureSQLInt(r, "maximum_write_bytes")
	case "maximum_requests >= 1":
		return resumeFixtureSQLInt(r, "maximum_requests") >= 1
	case "maximum_mutations <= maximum_requests":
		return resumeFixtureSQLInt(r, "maximum_mutations") <= resumeFixtureSQLInt(r, "maximum_requests")
	case "spent_mutations <= spent_requests":
		return resumeFixtureSQLInt(r, "spent_mutations") <= resumeFixtureSQLInt(r, "spent_requests")
	case "spent_reads + spent_lists + spent_creates + spent_deletes = spent_requests":
		return resumeFixtureSQLInt(r, "spent_reads")+resumeFixtureSQLInt(r, "spent_lists")+resumeFixtureSQLInt(r, "spent_creates")+resumeFixtureSQLInt(r, "spent_deletes") == resumeFixtureSQLInt(r, "spent_requests")
	case "spent_mutations = spent_creates + spent_deletes":
		return resumeFixtureSQLInt(r, "spent_mutations") == resumeFixtureSQLInt(r, "spent_creates")+resumeFixtureSQLInt(r, "spent_deletes")
	case "spent_pages = spent_lists":
		return resumeFixtureSQLInt(r, "spent_pages") == resumeFixtureSQLInt(r, "spent_lists")
	default:
		panic("unregistered SQL CHECK expression")
	}
}

func (s *resumeFixtureSQLService) beginCount(label string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begins[label]
}

var resumeScopedStatements = map[string]bool{"allowance_insert": true, "allowance_lock": true, "allowance_read": true, "allowance_spend": true, "allowance_totals": true, "attempt_insert": true, "attempt_read": true, "attempt_identity_read": true, "attempt_page": true, "evidence_insert": true, "evidence_identity_read": true, "evidence_slot_read": true, "evidence_attempt_read": true, "unresolved_exists": true, "unknown_exists": true, "unrecorded_uncertainty_page": true}
var resumeDimensions = []string{"requests", "mutations", "reads", "lists", "creates", "deletes", "pages", "versions", "response_bytes", "list_bytes", "write_bytes"}
var resumeScopeColumns = []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity"}

func (tx *resumeFixtureTransaction) resumeStatement(id string, a []driver.Value, query bool) ([][]driver.Value, int64, error) {
	s := tx.conn.s
	mutation := id == "allowance_insert" || id == "allowance_spend" || id == "attempt_insert" || id == "evidence_insert"
	if query == mutation {
		return nil, 0, s.fail("resume query method")
	}
	if mutation || id == "allowance_lock" {
		if tx.options.Isolation != driver.IsolationLevel(sql.LevelSerializable) || tx.options.ReadOnly || len(tx.held) != 1 {
			return nil, 0, s.fail("resume serializable artifact lock")
		}
	} else if tx.options.Isolation != driver.IsolationLevel(sql.LevelSerializable) && tx.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, 0, s.fail("resume snapshot isolation")
	}
	scoped := func(table, last string, values []driver.Value) []resumeFixtureRow {
		cols := append([]string(nil), resumeScopeColumns...)
		if last != "" {
			cols = append(cols, last)
		}
		return tx.lookup(table, cols, values)
	}
	projection := func(rows []resumeFixtureRow) [][]driver.Value {
		out := make([][]driver.Value, 0, len(rows))
		for _, r := range rows {
			out = append(out, resumeFixtureProject(r, resumeFixtureNames(s.registry[id].Columns)))
		}
		return out
	}
	permitted := func(table string, insert bool) bool {
		p := tx.catalog.Rows[erasureCatalogKey("table_privileges", tx.catalog.OIDs[table])]
		return len(p) == 1 && p[0][0] == true && p[0][1] == true && (!insert || p[0][2] == true)
	}
	for _, table := range map[string][]string{"allowance_totals": {resumeAttempts}, "attempt_read": {resumeAttempts}, "attempt_identity_read": {resumeAttempts}, "attempt_page": {resumeAttempts}, "evidence_identity_read": {resumeEvidence}, "evidence_slot_read": {resumeEvidence}, "evidence_attempt_read": {resumeEvidence}, "unknown_exists": {resumeEvidence}, "unresolved_exists": {resumeAttempts, resumeEvidence}, "unrecorded_uncertainty_page": {resumeAttempts, resumeEvidence}}[id] {
		if !permitted(table, false) {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
	}
	if mutation && id != "allowance_spend" {
		table := map[string]string{"allowance_insert": resumeAllowances, "attempt_insert": resumeAttempts, "evidence_insert": resumeEvidence}[id]
		if !permitted(table, true) {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
		row := resumeFixtureRow{}
		for i, p := range s.registry[id].Parameters {
			row[strings.SplitN(p, ":", 2)[0]] = resumeFixtureCopyValue(a[i])
		}
		wanted := "artifact:" + resumeFixtureSQLText(row, "scope_identity") + ":" + resumeFixtureSQLText(row, "artifact_identity")
		if !tx.held[wanted] {
			return nil, 0, s.fail("resume wrong artifact advisory key")
		}
		if len(tx.rows[table]) >= 8192 {
			return nil, 0, s.fail("resume table bound")
		}
		if id == "attempt_insert" {
			lock := "allowance:" + resumeTupleKey(resumeFixtureTuple(row, append(append([]string(nil), resumeScopeColumns...), "allowance_identity")))
			if s.rowLocks[lock] != tx.id {
				return nil, 0, s.fail("attempt without allowance row lock")
			}
		}
		tx.rows[table] = append(tx.rows[table], row)
		if err := tx.validateTables(); err != nil {
			tx.rows[table] = tx.rows[table][:len(tx.rows[table])-1]
			return nil, 0, err
		}
		tx.dirty = true
		return nil, 1, nil
	}
	switch id {
	case "allowance_read", "allowance_lock", "allowance_spend":
		if !permitted(resumeAllowances, false) {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
		rows := scoped(resumeAllowances, "allowance_identity", a[:6])
		lock := "allowance:" + resumeTupleKey(a[:6])
		if id == "allowance_lock" && len(rows) > 0 {
			for _, r := range rows {
				if !tx.held["artifact:"+resumeFixtureSQLText(r, "scope_identity")+":"+resumeFixtureSQLText(r, "artifact_identity")] {
					return nil, 0, s.fail("allowance common lock")
				}
			}
			if owner := s.rowLocks[lock]; owner != 0 && owner != tx.id {
				return nil, 0, &pgconn.PgError{Code: "40001"}
			}
			s.rowLocks[lock] = tx.id
		}
		if id != "allowance_spend" {
			return projection(rows), 0, nil
		}
		if s.rowLocks[lock] != tx.id {
			return nil, 0, s.fail("spend without allowance row lock")
		}
		grants := tx.catalog.Rows[erasureCatalogKey("allowance_counter_privileges", tx.catalog.OIDs[resumeAllowances])]
		if len(grants) != 1 {
			return nil, 0, &pgconn.PgError{Code: "42501"}
		}
		for _, g := range grants[0] {
			if g != true {
				return nil, 0, &pgconn.PgError{Code: "42501"}
			}
		}
		count := int64(0)
		for _, row := range rows {
			ok := true
			for i, d := range resumeDimensions {
				old, delta := resumeFixtureSQLInt(row, "spent_"+d), a[6+i].(int64)
				if delta > 0 && old > int64(9223372036854775807)-delta {
					return nil, 0, &pgconn.PgError{Code: "22003"}
				}
				if old+delta > resumeFixtureSQLInt(row, "maximum_"+d) {
					ok = false
				}
			}
			if !ok {
				continue
			}
			for i, d := range resumeDimensions {
				row["spent_"+d] = resumeFixtureSQLInt(row, "spent_"+d) + a[6+i].(int64)
			}
			count++
		}
		if count > 0 {
			if err := tx.validateTables(); err != nil {
				return nil, 0, err
			}
			tx.dirty = true
		}
		return nil, count, nil
	case "allowance_totals":
		rows := scoped(resumeAttempts, "allowance_identity", a)
		totals := make([]driver.Value, 12)
		totals[0] = int64(len(rows))
		for i, d := range resumeDimensions {
			sum := int64(0)
			for _, r := range rows {
				sum += resumeFixtureSQLInt(r, "cost_"+d)
			}
			totals[i+1] = sum
		}
		return [][]driver.Value{totals}, 0, nil
	case "attempt_read", "attempt_identity_read":
		last := "reservation_identity"
		if id == "attempt_identity_read" {
			last = "attempt_identity"
		}
		return projection(scoped(resumeAttempts, last, a)), 0, nil
	case "attempt_page":
		limit := a[7].(int64)
		if limit < 1 || limit > 65 {
			return nil, 0, s.fail("attempt page bound")
		}
		rows := scoped(resumeAttempts, "allowance_identity", a[:6])
		var kept []resumeFixtureRow
		for _, r := range rows {
			if resumeFixtureSQLInt(r, "sequence") > a[6].(int64) {
				kept = append(kept, r)
			}
		}
		sort.Slice(kept, func(i, j int) bool {
			return resumeFixtureSQLInt(kept[i], "sequence") < resumeFixtureSQLInt(kept[j], "sequence")
		})
		if len(kept) > int(limit) {
			kept = kept[:limit]
		}
		return projection(kept), 0, nil
	case "evidence_identity_read", "evidence_slot_read", "evidence_attempt_read":
		last := map[string]string{"evidence_identity_read": "evidence_identity", "evidence_slot_read": "slot", "evidence_attempt_read": "attempt_identity"}[id]
		rows := scoped(resumeEvidence, last, a)
		if id == "evidence_attempt_read" {
			sort.Slice(rows, func(i, j int) bool {
				return resumeFixtureSQLText(rows[i], "slot") < resumeFixtureSQLText(rows[j], "slot")
			})
			if len(rows) > 3 {
				rows = rows[:3]
			}
		}
		return projection(rows), 0, nil
	case "unknown_exists":
		for _, r := range scoped(resumeEvidence, "", a) {
			if r["kind"] == "unknown" {
				return [][]driver.Value{{true}}, 0, nil
			}
		}
		return [][]driver.Value{{false}}, 0, nil
	case "unresolved_exists", "unrecorded_uncertainty_page":
		all := scoped(resumeAttempts, "", a[:5])
		evidence := scoped(resumeEvidence, "", a[:5])
		var selected []resumeFixtureRow
		for _, r := range all {
			response, unknown := false, false
			for _, e := range evidence {
				if e["attempt_identity"] == r["attempt_identity"] {
					response = response || e["kind"] == "response"
					unknown = unknown || e["kind"] == "unknown"
				}
			}
			if id == "unresolved_exists" && !response {
				return [][]driver.Value{{true}}, 0, nil
			}
			if id == "unrecorded_uncertainty_page" && !response && !unknown && resumeFixtureSQLText(r, "attempt_identity") > a[5].(string) {
				selected = append(selected, r)
			}
		}
		if id == "unresolved_exists" {
			return [][]driver.Value{{false}}, 0, nil
		}
		limit := a[6].(int64)
		if limit < 1 || limit > 65 {
			return nil, 0, s.fail("uncertainty page bound")
		}
		sort.Slice(selected, func(i, j int) bool {
			return resumeFixtureSQLText(selected[i], "attempt_identity") < resumeFixtureSQLText(selected[j], "attempt_identity")
		})
		if len(selected) > int(limit) {
			selected = selected[:limit]
		}
		return projection(selected), 0, nil
	}
	return nil, 0, s.fail("unknown resume statement")
}
func resumeDecodeObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal("external canonical JSON", err)
	}
	return v
}

func (s *resumeFixtureSQLService) DropExistingForFault(table, column string, value driver.Value, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if label == "" || len(s.active) != 0 {
		return s.fail("unlabeled or active corruption")
	}
	for i, row := range s.rows[table] {
		if reflect.DeepEqual(row[column], value) {
			s.rows[table] = append(s.rows[table][:i], s.rows[table][i+1:]...)
			s.revision++
			return nil
		}
	}
	return s.fail("corruption requires product-written row")
}

func resumeTupleKey(values []driver.Value) string {
	raw, err := json.Marshal(values)
	if err != nil {
		panic("external tuple key")
	}
	return string(raw)
}
