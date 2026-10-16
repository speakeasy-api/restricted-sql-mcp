// Package multidb serves several databases of one Postgres server from one
// process. The DSN's database is the default and is always served; further
// databases whose names match a pattern are opened lazily on first use, each
// with its own policy, provisioned roles and pools, and are torn down when
// the database disappears.
package multidb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/txn"
)

const (
	// openTimeout bounds opening one database: schema expansion, role
	// provisioning and the first ping.
	openTimeout = 30 * time.Second
	// catalogTimeout bounds one pg_database query on the bootstrap connection.
	catalogTimeout = 10 * time.Second
	// recheckInterval rate-limits existence checks triggered by connection
	// errors that do not by themselves prove the database is gone.
	recheckInterval = time.Second
	// closeTimeout bounds closing an evicted instance's pools.
	closeTimeout = 2 * time.Second
	// dropTimeout bounds dropping an evicted instance's roles.
	dropTimeout = 10 * time.Second
)

// ErrUnknownDatabase is returned for databases that are not served: the name
// does not match the pattern, does not exist, or disappeared.
var ErrUnknownDatabase = errors.New("unknown database")

var errClosed = errors.New("server is shutting down")

// Instance is one served database.
type Instance struct {
	Name    string
	Policy  *policy.Policy
	Backend db.Backend
	// Roles are the login roles provisioned for this database alone. They
	// are dropped when the database disappears. Empty for the default
	// database and without connection-level security.
	Roles []string

	inner db.Backend // the unwrapped backend, closed on eviction
}

// Opener opens a database that matched the pattern and exists. It returns
// an instance whose Backend is ready to serve, or an error, in which case it
// must have released everything it acquired.
type Opener func(ctx context.Context, name string) (*Instance, error)

// Options configures a Manager.
type Options struct {
	// BootstrapDSN connects to the default database. It enumerates
	// databases, checks whether one still exists, and drops evicted roles.
	BootstrapDSN string
	// Default is the DSN's database. It is never evicted.
	Default *Instance
	// Pattern selects the further databases to serve.
	Pattern *regexp.Regexp
	Open    Opener
	// Txns, when set, has the transactions of an evicted database rolled back.
	Txns   *txn.Registry
	Logger *slog.Logger
}

// Info describes one served database.
type Info struct {
	Name    string `json:"name" jsonschema:"database name; pass it as the database argument"`
	Default bool   `json:"default" jsonschema:"true for the database used when the database argument is omitted"`
	Open    bool   `json:"open" jsonschema:"true when the server already holds connections to it"`
}

type call struct {
	done chan struct{}
	inst *Instance
	err  error
}

// Manager resolves database names to instances.
type Manager struct {
	opts Options
	log  *slog.Logger

	refreshMu sync.Mutex // serialises enumerate-and-apply so a stale list never wins

	mu        sync.Mutex
	instances map[string]*Instance // open non-default databases
	known     map[string]bool      // matching databases from the last refresh
	loading   map[string]*call
	evicting  map[string]chan struct{}
	lastCheck map[string]time.Time
	closed    bool
}

// New builds a Manager. It does not touch the database.
func New(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Manager{
		opts:      opts,
		log:       opts.Logger.With("component", "multidb"),
		instances: map[string]*Instance{},
		known:     map[string]bool{},
		loading:   map[string]*call{},
		evicting:  map[string]chan struct{}{},
		lastCheck: map[string]time.Time{},
	}
}

// Default returns the name of the default database.
func (m *Manager) Default() string { return m.opts.Default.Name }

func unknown(name string) error {
	return fmt.Errorf("%w %q: it is not served by this server or no longer exists; call list_databases for the served databases", ErrUnknownDatabase, name)
}

// Get returns the instance serving name, opening it on first use. An empty
// name is the default database. A name that is not known from the last
// refresh triggers one refresh before it is reported unknown.
func (m *Manager) Get(ctx context.Context, name string) (*Instance, error) {
	if name == "" || name == m.opts.Default.Name {
		return m.opts.Default, nil
	}
	if !m.opts.Pattern.MatchString(name) {
		return nil, unknown(name)
	}
	m.mu.Lock()
	inst, known := m.instances[name], m.known[name]
	m.mu.Unlock()
	if inst != nil {
		return inst, nil
	}
	if !known {
		if _, err := m.Refresh(ctx); err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		m.mu.Lock()
		known = m.known[name]
		m.mu.Unlock()
		if !known {
			return nil, unknown(name)
		}
	}
	return m.load(ctx, name)
}

// load opens name once no matter how many callers ask concurrently. The open
// runs detached from the caller so one cancelled request does not fail the
// others; a failure is not cached.
func (m *Manager) load(ctx context.Context, name string) (*Instance, error) {
	m.mu.Lock()
	if inst := m.instances[name]; inst != nil {
		m.mu.Unlock()
		return inst, nil
	}
	if m.closed {
		m.mu.Unlock()
		return nil, errClosed
	}
	c := m.loading[name]
	if c == nil {
		c = &call{done: make(chan struct{})}
		m.loading[name] = c
		go m.open(name, c)
	}
	m.mu.Unlock()
	select {
	case <-c.done:
		return c.inst, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Manager) open(name string, c *call) {
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	// A previous instance of the same name may still be dropping its roles;
	// let it finish so it cannot drop the roles this open provisions.
	m.mu.Lock()
	evicting := m.evicting[name]
	m.mu.Unlock()
	if evicting != nil {
		select {
		case <-evicting:
		case <-ctx.Done():
		}
	}
	start := time.Now()
	inst, err := m.opts.Open(ctx, name)
	var discard *Instance
	m.mu.Lock()
	delete(m.loading, name)
	switch {
	case err != nil:
		if goneCode(err) {
			delete(m.known, name)
			err = fmt.Errorf("%w (%v)", unknown(name), err)
		} else {
			err = fmt.Errorf("open database %q: %w", name, err)
		}
	case m.closed:
		discard, inst, err = inst, nil, errClosed
	default:
		inst.inner = inst.Backend
		inst.Backend = m.watch(inst)
		m.instances[name] = inst
	}
	open := len(m.instances)
	m.mu.Unlock()
	if discard != nil {
		closeBackend(discard.Backend, m.log)
	}
	c.inst, c.err = inst, err
	close(c.done)
	if err != nil {
		m.log.Warn("database open failed; the next request retries", "database", name, "duration", time.Since(start).String(), "error", err.Error())
		return
	}
	m.log.Info("database opened", "database", name, "roles", inst.Roles, "read_tables", len(inst.Policy.ReadTables),
		"write_tables", len(inst.Policy.WriteTables), "open_databases", open, "duration", time.Since(start).String())
}

// Refresh re-reads the database list, evicts open databases that are no
// longer listed, and returns the served names, default first.
func (m *Manager) Refresh(ctx context.Context) ([]string, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	names, err := m.enumerate(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	m.mu.Lock()
	for _, n := range names {
		// A database being evicted was confirmed gone after this list may
		// have been read; do not resurrect it.
		if n != m.opts.Default.Name && m.opts.Pattern.MatchString(n) && m.evicting[n] == nil {
			known[n] = true
		}
	}
	m.known = known
	var gone []*Instance
	for n, inst := range m.instances {
		if !known[n] {
			gone = append(gone, inst)
		}
	}
	m.mu.Unlock()
	for _, inst := range gone {
		m.evict(inst, "database is no longer listed")
	}
	served := []string{m.opts.Default.Name}
	for n := range known {
		served = append(served, n)
	}
	sort.Strings(served[1:])
	return served, nil
}

// List refreshes the database list and the column snapshots of the open
// databases, and describes every served database.
func (m *Manager) List(ctx context.Context) ([]Info, error) {
	names, err := m.Refresh(ctx)
	if err != nil {
		return nil, err
	}
	m.RefreshColumns(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(names))
	for i, n := range names {
		out = append(out, Info{Name: n, Default: i == 0, Open: i == 0 || m.instances[n] != nil})
	}
	return out, nil
}

// RefreshColumns reloads the catalog column snapshot of every open
// additional database, so columns added by a migration become resolvable.
// Failures are logged; an error that shows the database is gone evicts it.
func (m *Manager) RefreshColumns(ctx context.Context) {
	m.mu.Lock()
	insts := make([]*Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		insts = append(insts, inst)
	}
	m.mu.Unlock()
	for _, inst := range insts {
		loader, ok := inst.Backend.(db.ColumnLoader)
		if !ok {
			continue
		}
		if err := loader.RefreshColumns(ctx); err != nil {
			m.log.Warn("column snapshot refresh failed", "database", inst.Name, "error", err.Error())
		}
	}
}

// RunColumnRefresh calls RefreshColumns every interval until ctx ends.
func (m *Manager) RunColumnRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, catalogTimeout)
			m.RefreshColumns(refreshCtx)
			cancel()
		}
	}
}

func (m *Manager) enumerate(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	conn, err := pgx.Connect(ctx, m.opts.BootstrapDSN)
	if err != nil {
		return nil, fmt.Errorf("bootstrap connection: %w", err)
	}
	defer closeConn(conn)
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_catalog.pg_database
WHERE datallowconn AND NOT datistemplate AND has_database_privilege(oid, 'CONNECT')
ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (m *Manager) exists(ctx context.Context, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	conn, err := pgx.Connect(ctx, m.opts.BootstrapDSN)
	if err != nil {
		return false, fmt.Errorf("bootstrap connection: %w", err)
	}
	defer closeConn(conn)
	var ok bool
	err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1 AND datallowconn)`, name).Scan(&ok)
	return ok, err
}

// observe inspects an error from inst's backend. When it suggests the
// database is gone and pg_database confirms it, inst is evicted. It reports
// whether inst is no longer served.
func (m *Manager) observe(ctx context.Context, inst *Instance, err error) bool {
	if err == nil || !suspicious(err) {
		return false
	}
	m.mu.Lock()
	if m.instances[inst.Name] != inst {
		m.mu.Unlock()
		return true
	}
	if !goneCode(err) && time.Since(m.lastCheck[inst.Name]) < recheckInterval {
		m.mu.Unlock()
		return false
	}
	m.lastCheck[inst.Name] = time.Now()
	m.mu.Unlock()

	ok, checkErr := m.exists(context.WithoutCancel(ctx), inst.Name)
	if checkErr != nil {
		m.log.Warn("could not check whether a database still exists", "database", inst.Name, "trigger", err.Error(), "error", checkErr.Error())
		return false
	}
	if ok {
		m.log.Debug("database still exists after a connection error", "database", inst.Name, "trigger", err.Error())
		return false
	}
	m.evict(inst, "database no longer exists: "+err.Error())
	return true
}

// evict stops serving inst: new requests see an unknown database, open
// transactions are rolled back, pools closed, and its roles dropped.
func (m *Manager) evict(inst *Instance, reason string) {
	name := inst.Name
	m.mu.Lock()
	if m.instances[name] != inst {
		m.mu.Unlock()
		return
	}
	delete(m.instances, name)
	delete(m.known, name)
	delete(m.lastCheck, name)
	done := make(chan struct{})
	m.evicting[name] = done
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.evicting[name] == done {
			delete(m.evicting, name)
		}
		m.mu.Unlock()
		close(done)
	}()

	log := m.log.With("database", name)
	log.Warn("database evicted", "reason", reason)
	if m.opts.Txns != nil {
		if n := m.opts.Txns.CloseDatabase(name); n > 0 {
			log.Info("open transactions of evicted database rolled back", "count", n)
		}
	}
	closeBackend(inst.inner, log)
	if len(inst.Roles) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
	defer cancel()
	dropped, err := dbsec.DropRoles(ctx, m.opts.BootstrapDSN, inst.Roles)
	if err != nil {
		log.Warn("dropping roles of evicted database failed", "dropped", dropped, "roles", inst.Roles, "error", err.Error())
		return
	}
	log.Info("roles of evicted database dropped", "roles", dropped)
}

// Close closes every non-default instance without dropping its roles. The
// default instance belongs to the caller.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	insts := make([]*Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		insts = append(insts, inst)
	}
	m.instances = map[string]*Instance{}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, inst := range insts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Roll back first: closing a pool waits for its pinned connections.
			if m.opts.Txns != nil {
				m.opts.Txns.CloseDatabase(inst.Name)
			}
			closeBackend(inst.inner, m.log.With("database", inst.Name))
		}()
	}
	wg.Wait()
}

// goneCode reports SQLSTATE 3D000 (invalid_catalog_name): the server says
// the database does not exist.
func goneCode(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "3D000"
}

// suspicious reports errors that may mean the database was dropped: missing
// database, administrator shutdown (DROP DATABASE ... WITH (FORCE) and
// pg_terminate_backend), connection exceptions, and errors with no SQLSTATE
// at all such as a broken connection. Ordinary SQL errors and cancellations
// are not.
func suspicious(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "3D000" || strings.HasPrefix(pgErr.Code, "57P") || strings.HasPrefix(pgErr.Code, "08")
	}
	return true
}

func closeBackend(b db.Backend, log *slog.Logger) {
	if b == nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	select {
	case err := <-done:
		if err != nil {
			log.Warn("closing database backend failed", "error", err.Error())
		}
	case <-time.After(closeTimeout):
		log.Warn("closing database backend did not finish in time; abandoning it", "waited", closeTimeout.String())
	}
}

func closeConn(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
