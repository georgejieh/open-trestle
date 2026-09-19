package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

type erasureRow map[string]driver.Value
type erasureRowsByTable map[string][]erasureRow
type erasureTestCommitMode uint8

const (
	erasureTestNormal erasureTestCommitMode = iota
	erasureTestKnownAbort
	erasureTestPersistThenLose
	erasureTestLoseWithoutPersist
)

type erasureSQLFault struct {
	StatementID       string
	Occurrence        int
	OperationLabel    string
	Err               error
	CommitMode        erasureTestCommitMode
	RollbackErr       error
	AffectedRows      *int64
	NextErr, CloseErr error
	NextAt            int
	Entered           chan struct{}
	Release           <-chan struct{}
	seen              int
}
type erasureTraceEvent struct {
	Sequence              uint64
	Graph, OperationLabel string
	TransactionID         uint64
	StatementID, Kind     string
	Persisted, ReplyKnown bool
	Isolation             driver.IsolationLevel
	ReadOnly              bool
}
type erasureSQLSnapshot struct {
	Rows          erasureRowsByTable
	Revision      uint64
	Events        []erasureTraceEvent
	Active, Locks int
	Errors        []string
}
type erasureSQLService struct {
	mu                               sync.Mutex
	t                                *testing.T
	registry                         map[string]erasureStatement
	catalog                          erasureCatalog
	rows                             erasureRowsByTable
	revision, next                   uint64
	handles, connections, statements int
	begins                           map[string]int
	events                           []erasureTraceEvent
	failures                         []string
	active                           map[uint64]*erasureTransaction
	locks                            map[string]chan struct{}
	rowLocks                         map[string]uint64
	faults                           []*erasureSQLFault
}
type erasureContextKey struct{}

func erasureOperationContext(t *testing.T, label string) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.WithValue(context.Background(), erasureContextKey{}, label), 5*time.Second)
}
func erasureLabel(ctx context.Context) string {
	s, _ := ctx.Value(erasureContextKey{}).(string)
	return s
}
func newErasureSQLService(t *testing.T, catalog erasureCatalog) *erasureSQLService {
	t.Helper()
	s := &erasureSQLService{t: t, registry: erasureRegistry(t), catalog: catalog, begins: map[string]int{}, rows: erasureRowsByTable{}, active: map[uint64]*erasureTransaction{}, locks: map[string]chan struct{}{}, rowLocks: map[string]uint64{}}
	for _, name := range erasureTableNames {
		s.rows[name] = nil
	}
	return s
}
func (s *erasureSQLService) fail(message string) error {
	s.failures = append(s.failures, message)
	return errors.New("external SQL fixture: " + message)
}
func (s *erasureSQLService) event(tx *erasureTransaction, id, kind string, persisted, known bool) {
	if len(s.events) >= 8192 {
		s.failures = append(s.failures, "event bound exceeded")
		return
	}
	e := erasureTraceEvent{Sequence: uint64(len(s.events) + 1), StatementID: id, Kind: kind, Persisted: persisted, ReplyKnown: known}
	if tx != nil {
		e.Graph = tx.conn.graph
		e.OperationLabel = tx.label
		e.TransactionID = tx.id
		e.Isolation = tx.options.Isolation
		e.ReadOnly = tx.options.ReadOnly
	}
	s.events = append(s.events, e)
}
func erasureCopyValue(v driver.Value) driver.Value {
	if b, ok := v.([]byte); ok {
		return append([]byte(nil), b...)
	}
	return v
}
func erasureCopyRows(rows [][]driver.Value) [][]driver.Value {
	out := make([][]driver.Value, len(rows))
	for i, row := range rows {
		out[i] = make([]driver.Value, len(row))
		for j, v := range row {
			out[i][j] = erasureCopyValue(v)
		}
	}
	return out
}
func erasureCopyTables(tables erasureRowsByTable) erasureRowsByTable {
	out := erasureRowsByTable{}
	for table, rows := range tables {
		for _, row := range rows {
			r := erasureRow{}
			for c, v := range row {
				r[c] = erasureCopyValue(v)
			}
			out[table] = append(out[table], r)
		}
		if len(rows) == 0 {
			out[table] = nil
		}
	}
	return out
}
func erasureCopyCatalog(c erasureCatalog) erasureCatalog {
	out := c
	out.Rows = map[string][][]driver.Value{}
	for id, rows := range c.Rows {
		out.Rows[id] = erasureCopyRows(rows)
	}
	out.OIDs = map[string]int64{}
	for n, v := range c.OIDs {
		out.OIDs[n] = v
	}
	return out
}
func (s *erasureSQLService) Snapshot() erasureSQLSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return erasureSQLSnapshot{erasureCopyTables(s.rows), s.revision, append([]erasureTraceEvent(nil), s.events...), len(s.active), len(s.locks) + len(s.rowLocks), append([]string(nil), s.failures...)}
}
func (s *erasureSQLService) Inject(f erasureSQLFault) error {
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
func (s *erasureSQLService) fault(ctx context.Context, id, label string) *erasureSQLFault {
	s.mu.Lock()
	var found *erasureSQLFault
	for _, f := range s.faults {
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
func (s *erasureSQLService) MutateCatalog(mutation func(*erasureCatalog)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.active) != 0 {
		return s.fail("catalog edit with transaction open")
	}
	mutation(&s.catalog)
	return nil
}
func erasureTuple(row erasureRow, columns []string) []driver.Value {
	out := make([]driver.Value, len(columns))
	for i, c := range columns {
		out[i] = row[c]
	}
	return out
}
func (s *erasureSQLService) CorruptExistingRow(table string, key []driver.Value, column string, replacement driver.Value) error {
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
		if reflect.DeepEqual(erasureTuple(r, pk), key) {
			r[column] = erasureCopyValue(replacement)
			s.revision++
			return nil
		}
	}
	return s.fail("corruption row absent")
}
func (s *erasureSQLService) AssertClean(t *testing.T) {
	t.Helper()
	v := s.Snapshot()
	if v.Active != 0 || v.Locks != 0 || len(v.Errors) != 0 {
		t.Fatalf("SQL service not clean: active=%d locks=%d errors=%v", v.Active, v.Locks, v.Errors)
	}
}
func (s *erasureSQLService) OpenDB(t *testing.T, graph string) *sql.DB {
	t.Helper()
	s.mu.Lock()
	s.handles++
	if s.handles > 3 {
		s.mu.Unlock()
		t.Fatal("DB handle bound")
	}
	s.mu.Unlock()
	db := sql.OpenDB(erasureConnector{s, graph})
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type erasureConnector struct {
	s     *erasureSQLService
	graph string
}

func (c erasureConnector) Driver() driver.Driver { return erasureDriver{} }
func (c erasureConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.connections >= 6 {
		return nil, c.s.fail("connection bound")
	}
	c.s.connections++
	return &erasureConnection{s: c.s, graph: c.graph}, nil
}

type erasureDriver struct{}

func (erasureDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type erasureConnection struct {
	s      *erasureSQLService
	graph  string
	tx     *erasureTransaction
	closed bool
}

func (c *erasureConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements not in finite protocol")
}
func (c *erasureConnection) Begin() (driver.Tx, error) { return nil, errors.New("BeginTx required") }
func (c *erasureConnection) Close() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.s.connections--
	}
	return nil
}
func (c *erasureConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.s.mu.Lock()
	c.s.begins[erasureLabel(ctx)]++
	c.s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f := c.s.fault(ctx, "BEGIN", erasureLabel(ctx))
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
	tx := &erasureTransaction{conn: c, id: c.s.next, ctx: ctx, label: erasureLabel(ctx), options: options, rows: erasureCopyTables(c.s.rows), catalog: erasureCopyCatalog(c.s.catalog), revision: c.s.revision, held: map[string]bool{}}
	c.tx = tx
	c.s.active[tx.id] = tx
	c.s.event(tx, "BEGIN", "begin", false, false)
	return tx, nil
}
func erasureNormalizeSQL(q string) string {
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
func (c *erasureConnection) identify(q string, args []driver.NamedValue) (string, []driver.Value, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.statements++
	if c.s.statements > 4096 || len(q) > 32768 || len(args) > 32 {
		return "", nil, c.s.fail("SQL resource bound")
	}
	normalized := erasureNormalizeSQL(q)
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
			valid := false
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
			if !valid {
				return "", nil, c.s.fail("parameter type for " + id)
			}
			values[i] = erasureCopyValue(a.Value)
		}
		return id, values, nil
	}
	return "", nil, c.s.fail("unexpected SQL: " + normalized)
}
func (c *erasureConnection) run(ctx context.Context, q string, args []driver.NamedValue, query bool) (driver.Result, driver.Rows, error) {
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
	if tx.options.Isolation == driver.IsolationLevel(sql.LevelReadCommitted) && !tx.dirty {
		tx.rows = erasureCopyTables(c.s.rows)
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
	result := &erasureDriverRows{columns: columns, rows: erasureCopyRows(rows)}
	if f != nil {
		result.nextErr = f.NextErr
		result.closeErr = f.CloseErr
		result.nextAt = f.NextAt
	}
	return nil, result, nil
}
func (c *erasureConnection) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	r, _, e := c.run(ctx, q, a, false)
	return r, e
}
func (c *erasureConnection) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	_, r, e := c.run(ctx, q, a, true)
	return r, e
}

type erasureDriverRows struct {
	columns           []string
	rows              [][]driver.Value
	at, nextAt        int
	nextErr, closeErr error
	closed            bool
}

func (r *erasureDriverRows) Columns() []string { return r.columns }
func (r *erasureDriverRows) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.closeErr
}
func (r *erasureDriverRows) Next(dst []driver.Value) error {
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

type erasureTransaction struct {
	conn        *erasureConnection
	id          uint64
	ctx         context.Context
	label       string
	options     driver.TxOptions
	rows        erasureRowsByTable
	catalog     erasureCatalog
	revision    uint64
	tenant      string
	held        map[string]bool
	dirty, done bool
	rollbackErr error
}

func (tx *erasureTransaction) acquire(ctx context.Context, key string) error {
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
func (tx *erasureTransaction) finish() {
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
func (tx *erasureTransaction) Commit() error {
	s := tx.conn.s
	f := s.fault(tx.ctx, "COMMIT", tx.label)
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done {
		return sql.ErrTxDone
	}
	if f != nil && (f.CommitMode == erasureTestKnownAbort || f.CommitMode == erasureTestLoseWithoutPersist) {
		tx.finish()
		s.event(tx, "COMMIT", "no-persistence", false, false)
		return f.Err
	}
	if tx.dirty && tx.revision != s.revision {
		tx.finish()
		return &pgconn.PgError{Code: "40001"}
	}
	if f != nil && f.Err != nil && f.CommitMode != erasureTestPersistThenLose {
		tx.finish()
		s.event(tx, "COMMIT", "no-persistence", false, false)
		return f.Err
	}
	if tx.dirty {
		if err := tx.validateTables(); err != nil {
			tx.finish()
			return err
		}
		s.rows = erasureCopyTables(tx.rows)
		s.revision++
	}
	persisted := tx.dirty
	s.event(tx, "COMMIT", "durable", persisted, false)
	tx.finish()
	if f != nil && f.CommitMode == erasureTestPersistThenLose {
		return f.Err
	}
	s.event(tx, "COMMIT", "reply", persisted, true)
	return nil
}
func (tx *erasureTransaction) Rollback() error {
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
func (tx *erasureTransaction) lookup(table string, columns []string, values []driver.Value) []erasureRow {
	var out []erasureRow
	for _, r := range tx.rows[table] {
		if r["tenant_id"] != tx.tenant {
			continue
		}
		if reflect.DeepEqual(erasureTuple(r, columns), values) {
			out = append(out, r)
		}
	}
	return out
}
func erasureProject(row erasureRow, names []string) []driver.Value {
	out := make([]driver.Value, len(names))
	for i, n := range names {
		out[i] = erasureCopyValue(row[n])
	}
	return out
}
func erasureNames(columns []string) []string {
	out := make([]string, len(columns))
	for i, c := range columns {
		out[i] = strings.SplitN(c, ":", 2)[0]
	}
	return out
}
func (tx *erasureTransaction) statement(id string, a []driver.Value, query bool) ([][]driver.Value, int64, error) {
	s := tx.conn.s
	cat := id == "role" || id == "authority_schemas" || id == "authority_identity" || id == "migration_rows" || id == "relation" || id == "attributes" || id == "constraints" || id == "indexes" || id == "policies" || id == "table_privileges" || id == "confirmation_privileges"
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
			if id == "confirmation_privileges" && a[1] != tx.catalog.Role {
				return nil, 0, s.fail("column privilege binding")
			}
			k = erasureCatalogKey(id, oid)
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
	if (id == "admission_read" || id == "operation_read" || id == "operation_ref_read") && len(tx.held) == 0 && tx.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
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
		r := erasureRow{}
		for i, p := range s.registry[id].Parameters {
			r[strings.SplitN(p, ":", 2)[0]] = erasureCopyValue(a[i])
		}
		for _, c := range tx.catalog.Tables[table].Columns {
			if _, ok := r[c.Name]; !ok {
				if c.Default != nil {
					r[c.Name] = time.UnixMilli(1).UTC()
				} else {
					r[c.Name] = nil
				}
			}
		}
		if id == "scope_insert" {
			for _, old := range tx.rows[table] {
				for _, c := range tx.catalog.Tables[table].Constraints {
					if (c.Kind == "PRIMARY KEY" || c.Kind == "UNIQUE") && reflect.DeepEqual(erasureTuple(old, c.Columns), erasureTuple(r, c.Columns)) {
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
		if len(tx.rows[table]) >= 8 {
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
			out = append(out, erasureProject(r, erasureNames(s.registry[id].Columns)))
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
			values := erasureProject(r, erasureNames(s.registry["operation_insert"].Parameters))
			ac := []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}
			admitted := tx.lookup(erasureAdmissions, ac, erasureTuple(r, ac))
			var ar erasureRow
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
			if len(tx.lookup(erasureOperations, scoped, erasureTuple(r, scoped))) != 0 {
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
func (tx *erasureTransaction) joinAdmission(r erasureRow) []driver.Value {
	var names []string
	for _, c := range tx.catalog.Tables[erasureAdmissions].Columns {
		names = append(names, c.Name)
	}
	out := erasureProject(r, names)
	var scope, meta erasureRow
	if r != nil {
		sc := []string{"tenant_id", "repository_id", "review_run_id"}
		m := append(append([]string(nil), sc...), "artifact_identity")
		if found := tx.lookup(erasureScopes, sc, erasureTuple(r, sc)); len(found) > 0 {
			scope = found[0]
		}
		if found := tx.lookup(erasureMetadata, m, erasureTuple(r, m)); len(found) > 0 {
			meta = found[0]
		}
	}
	out = append(out, scope["scope_identity"])
	out = append(out, erasureProject(meta, []string{"scope_identity", "artifact_identity", "payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"})...)
	return out
}
func (tx *erasureTransaction) validateTables() error {
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
						if reflect.DeepEqual(erasureTuple(rows[j], c.Columns), erasureTuple(r, c.Columns)) {
							return &pgconn.PgError{Code: "23505"}
						}
					}
				case "FOREIGN KEY":
					found := false
					for _, foreign := range tx.rows[c.Target] {
						if reflect.DeepEqual(erasureTuple(r, c.Columns), erasureTuple(foreign, c.TargetColumns)) {
							found = true
							break
						}
					}
					if !found {
						return &pgconn.PgError{Code: "23503"}
					}
				case "CHECK":
					if !erasureSQLCheck(c.Expression, r) {
						return &pgconn.PgError{Code: "23514"}
					}
				}
			}
		}
	}
	if bytesTotal > 2097152 {
		return tx.conn.s.fail("canonical byte bound")
	}
	return nil
}
func erasureSQLText(r erasureRow, c string) string { v, _ := r[c].(string); return v }
func erasureSQLInt(r erasureRow, c string) int64   { v, _ := r[c].(int64); return v }
func erasureSQLBytes(r erasureRow, c string) int {
	switch v := r[c].(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	}
	return 0
}

var erasureSQLHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func erasureSQLCheck(expression string, r erasureRow) bool {
	switch expression {
	case "octet_length(tenant_id) BETWEEN 1 AND 128":
		if r["tenant_id"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "tenant_id")
		return n >= 1 && n <= 128
	case "octet_length(repository_id) BETWEEN 1 AND 128":
		if r["repository_id"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "repository_id")
		return n >= 1 && n <= 128
	case "octet_length(review_run_id) BETWEEN 1 AND 128":
		if r["review_run_id"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "review_run_id")
		return n >= 1 && n <= 128
	case "scope_identity ~ '^[0-9a-f]{64}$'":
		if r["scope_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "scope_identity")
		return erasureSQLHex.MatchString(v)
	case "artifact_identity ~ '^[0-9a-f]{64}$'":
		if r["artifact_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "artifact_identity")
		return erasureSQLHex.MatchString(v)
	case "payload_digest ~ '^[0-9a-f]{64}$'":
		if r["payload_digest"] == nil {
			return true
		}
		v := erasureSQLText(r, "payload_digest")
		return erasureSQLHex.MatchString(v)
	case "kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result')":
		if r["kind"] == nil {
			return true
		}
		switch erasureSQLText(r, "kind") {
		case "source_snapshot", "change_model", "deterministic_evidence", "retrieval_result", "context_packet", "candidate_batch", "verification_batch", "verified_finding_set", "publication_plan", "run_export", "task_input", "webhook_delivery", "source_file", "publication_receipt", "investigation_turn", "investigation_tool_result":
			return true
		}
		return false
	case "classification IN ('public', 'internal', 'confidential', 'restricted')":
		if r["classification"] == nil {
			return true
		}
		switch erasureSQLText(r, "classification") {
		case "public", "internal", "confidential", "restricted":
			return true
		}
		return false
	case "origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy', 'memory')":
		if r["origin"] == nil {
			return true
		}
		switch erasureSQLText(r, "origin") {
		case "host", "repository", "deterministic_tool", "model", "independent_verifier", "policy", "memory":
			return true
		}
		return false
	case "protection IN ('process_private', 'envelope_encrypted')":
		if r["protection"] == nil {
			return true
		}
		switch erasureSQLText(r, "protection") {
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
		v := erasureSQLText(r, "authorization_identity")
		return erasureSQLHex.MatchString(v)
	case "policy_identity ~ '^[0-9a-f]{64}$'":
		if r["policy_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "policy_identity")
		return erasureSQLHex.MatchString(v)
	case "hold_clearance_identity ~ '^[0-9a-f]{64}$'":
		if r["hold_clearance_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "hold_clearance_identity")
		return erasureSQLHex.MatchString(v)
	case "octet_length(principal_identity) BETWEEN 1 AND 128":
		if r["principal_identity"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "principal_identity")
		return n >= 1 && n <= 128
	case "reason IN ('expired', 'tenant_erasure', 'repository_erasure')":
		if r["reason"] == nil {
			return true
		}
		switch erasureSQLText(r, "reason") {
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
		v := erasureSQLText(r, "receipt_identity")
		return erasureSQLHex.MatchString(v)
	case "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["scope_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "scope_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["namespace_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "namespace_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["artifact_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "artifact_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["admission_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "admission_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["database_authority_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "database_authority_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["admitted_policy_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "admitted_policy_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_admission) BETWEEN 1 AND 16384":
		if r["canonical_admission"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "canonical_admission")
		return n >= 1 && n <= 16384
	case "octet_length(canonical_namespace) BETWEEN 1 AND 4096":
		if r["canonical_namespace"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "canonical_namespace")
		return n >= 1 && n <= 4096
	case "octet_length(admitted_policy) BETWEEN 1 AND 16384":
		if r["admitted_policy"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "admitted_policy")
		return n >= 1 && n <= 16384
	case "admitted_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["admitted_at_milliseconds"] == nil {
			return true
		}
		v := erasureSQLInt(r, "admitted_at_milliseconds")
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
		v := erasureSQLText(r, "confirmed_version")
		d := erasureSQLText(r, "confirmed_ciphertext_digest")
		at := erasureSQLInt(r, "confirmed_at_milliseconds")
		return strings.HasPrefix(v, "version:") && len(v) >= 9 && len(v) <= 512 && v != "version:null" && utf8.ValidString(v) && strings.IndexFunc(v, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) < 0 && erasureSQLHex.MatchString(d) && d != strings.Repeat("0", 64) && at >= 1 && at <= 253402300799999 && at >= erasureSQLInt(r, "admitted_at_milliseconds")
	case "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["operation_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "operation_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["authorization_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "authorization_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["authorization_document_digest"] == nil {
			return true
		}
		v := erasureSQLText(r, "authorization_document_digest")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'":
		if r["protected_policy_identity"] == nil {
			return true
		}
		v := erasureSQLText(r, "protected_policy_identity")
		return erasureSQLHex.MatchString(v) && v != strings.Repeat("0", 64)
	case "octet_length(canonical_operation) BETWEEN 1 AND 16384":
		if r["canonical_operation"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "canonical_operation")
		return n >= 1 && n <= 16384
	case "octet_length(canonical_authorization) BETWEEN 1 AND 8192":
		if r["canonical_authorization"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "canonical_authorization")
		return n >= 1 && n <= 8192
	case "octet_length(accepted_policy) BETWEEN 1 AND 16384":
		if r["accepted_policy"] == nil {
			return true
		}
		n := erasureSQLBytes(r, "accepted_policy")
		return n >= 1 && n <= 16384
	case "prepared_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["prepared_at_milliseconds"] == nil {
			return true
		}
		v := erasureSQLInt(r, "prepared_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "accepted_at_milliseconds BETWEEN 1 AND 253402300799999":
		if r["accepted_at_milliseconds"] == nil {
			return true
		}
		v := erasureSQLInt(r, "accepted_at_milliseconds")
		return v >= 1 && v <= 253402300799999
	case "accepted_at_milliseconds >= prepared_at_milliseconds":
		return erasureSQLInt(r, "accepted_at_milliseconds") >= erasureSQLInt(r, "prepared_at_milliseconds")
	default:
		panic("unregistered SQL CHECK expression")
	}
}

func (s *erasureSQLService) beginCount(label string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begins[label]
}
