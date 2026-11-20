'use strict';
// Read-only Neon STAGING preflight utility (P0.4.5-B).
// Zero writes, zero DDL/DML, zero fallback to runtime/migration/admin DB variables,
// and mandatory endpoint ID match against NEON_STAGING_EXPECTED_ENDPOINT_ID before opening any Pool.

const { loadEnvFiles, safeError, redactSecrets, isPoolerHostname } = require('../db/_lib/direct-db');

const ALLOWED_PREFLIGHT_ENV_VARS = Object.freeze([
  'NEON_STAGING_PREFLIGHT_DIRECT_URL',
  'NEON_STAGING_PREFLIGHT_POOLED_URL',
  'NEON_STAGING_EXPECTED_ENDPOINT_ID'
]);

const FORBIDDEN_FALLBACK_VARS = Object.freeze([
  'DATABASE_URL',
  'DIRECT_DATABASE_URL',
  'DIRECT_ADMIN_DATABASE_URL'
]);

const EXPECTED_ADMIN_ROLE = 'neondb_owner';
const EXPECTED_DATABASE = 'neondb';
const ENDPOINT_ID_RE = /^ep-[a-z0-9]+(?:-[a-z0-9]+)+$/;
const WRITE_OR_DDL_RE =
  /\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|VACUUM|REASSIGN|SECURITY|COMMENT)\b/i;

const KNOWN_ARKIK_RELATIONS = new Set([
  'schema_migrations',
  'bookings',
  'availability',
  'audit_log',
  'config',
  'admin_credentials',
  'admin_sessions',
  'idempotency_keys',
  'rate_limits',
  'audit_log_id_seq'
]);

const PREFLIGHT_SQL = Object.freeze({
  BEGIN_RO: 'BEGIN READ ONLY',
  SET_STATEMENT_TIMEOUT: 'SET LOCAL statement_timeout = 8000',
  SET_LOCK_TIMEOUT: 'SET LOCAL lock_timeout = 3000',
  SET_IDLE_IN_TX_TIMEOUT: 'SET LOCAL idle_in_transaction_session_timeout = 10000',
  ROLLBACK: 'ROLLBACK',
  PROBE_IDENTITY: [
    'SELECT current_database() AS current_database,',
    'current_user AS current_user,',
    'session_user AS session_user,',
    "current_setting('server_version') AS server_version,",
    "current_setting('server_version_num')::int AS server_version_num"
  ].join(' '),
  READ_TIMEOUT_SETTINGS: [
    "SELECT current_setting('statement_timeout') AS statement_timeout,",
    "current_setting('lock_timeout') AS lock_timeout,",
    "current_setting('idle_in_transaction_session_timeout') AS idle_in_transaction_session_timeout,",
    "current_setting('transaction_read_only') AS transaction_read_only"
  ].join(' '),
  INSPECT_ROLES: [
    'SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb,',
    'r.rolcanlogin, r.rolreplication, r.rolbypassrls,',
    "pg_has_role(r.rolname, 'neon_superuser', 'MEMBER') AS member_of_neon_superuser,",
    "pg_has_role(r.rolname, 'neon_superuser', 'USAGE') AS effective_neon_superuser",
    'FROM pg_roles r',
    "WHERE r.rolname IN ('neondb_owner', 'neon_superuser', 'arkik_migrator', 'arkik_admin', 'arkik_app')",
    'ORDER BY r.rolname ASC'
  ].join(' '),
  INSPECT_ROLE_MEMBERSHIPS: [
    'SELECT role_r.rolname AS role_name,',
    'member_r.rolname AS member_name,',
    'COALESCE(grantor_r.rolname, pg_get_userbyid(am.grantor)) AS grantor_name,',
    'am.admin_option, am.inherit_option, am.set_option',
    'FROM pg_auth_members am',
    'JOIN pg_roles role_r ON role_r.oid = am.roleid',
    'JOIN pg_roles member_r ON member_r.oid = am.member',
    'LEFT JOIN pg_roles grantor_r ON grantor_r.oid = am.grantor',
    "WHERE member_r.rolname IN ('neondb_owner', 'neon_superuser', 'arkik_migrator', 'arkik_admin', 'arkik_app')",
    "OR role_r.rolname IN ('neon_superuser', 'arkik_migrator', 'arkik_admin', 'arkik_app')",
    'ORDER BY role_r.rolname ASC, member_r.rolname ASC'
  ].join(' '),
  INSPECT_DB_AND_SCHEMA_PRIVILEGES: [
    'SELECT d.datname AS database_name,',
    'pg_get_userbyid(d.datdba) AS db_owner,',
    'n.nspname AS schema_name,',
    'pg_get_userbyid(n.nspowner) AS schema_owner,',
    "pg_has_role(current_user, d.datdba, 'USAGE') AS has_db_owner_role,",
    "pg_has_role(current_user, n.nspowner, 'USAGE') AS has_schema_owner_role,",
    "has_database_privilege(current_user, d.datname, 'CONNECT') AS owner_db_connect,",
    "has_database_privilege(current_user, d.datname, 'CREATE') AS owner_db_create,",
    "has_schema_privilege(current_user, n.nspname, 'USAGE') AS owner_schema_usage,",
    "has_schema_privilege(current_user, n.nspname, 'CREATE') AS owner_schema_create,",
    "has_schema_privilege('public', n.nspname, 'CREATE') AS public_schema_create",
    'FROM pg_database d',
    "JOIN pg_namespace n ON n.nspname = 'public'",
    'WHERE d.datname = current_database()'
  ].join(' '),
  INVENTORY_RELATIONS: [
    'SELECT n.nspname AS schema_name,',
    'c.relname AS object_name,',
    'c.relkind,',
    "CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned_table' WHEN 'S' THEN 'sequence' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' WHEN 'f' THEN 'foreign_table' ELSE 'other' END AS object_type,",
    'pg_get_userbyid(c.relowner) AS owner_name,',
    '(SELECT ext.extname FROM pg_depend dep JOIN pg_extension ext ON ext.oid = dep.refobjid',
    "WHERE dep.classid = 'pg_class'::regclass AND dep.objid = c.oid AND dep.refclassid = 'pg_extension'::regclass AND dep.deptype IN ('e', 'a', 'i')",
    'ORDER BY dep.deptype ASC LIMIT 1) AS owning_extension',
    'FROM pg_class c',
    'JOIN pg_namespace n ON n.oid = c.relnamespace',
    "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')",
    "AND n.nspname !~ '^pg_(toast|temp)'",
    "AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')",
    'ORDER BY n.nspname ASC, c.relkind ASC, c.relname ASC'
  ].join(' '),
  INVENTORY_EXTENSIONS: [
    'SELECT e.extname AS extension_name,',
    'e.extversion AS extension_version,',
    'n.nspname AS schema_name,',
    'pg_get_userbyid(e.extowner) AS owner_name',
    'FROM pg_extension e',
    'JOIN pg_namespace n ON n.oid = e.extnamespace',
    'ORDER BY e.extname ASC'
  ].join(' '),
  INVENTORY_EXTENSION_OBJECTS: [
    'SELECT e.extname AS extension_name,',
    'd.classid::regclass::text AS object_class,',
    'pg_describe_object(d.classid, d.objid, d.objsubid) AS object_description',
    'FROM pg_depend d',
    'JOIN pg_extension e ON e.oid = d.refobjid',
    "WHERE d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'",
    'ORDER BY e.extname ASC, object_description ASC'
  ].join(' ')
});

const ALLOWED_SQL_SET = new Set(Object.values(PREFLIGHT_SQL));

function sanitizePreflightText(value, extraSecrets = []) {
  let out = redactSecrets(String(value || ''));
  for (const item of extraSecrets) {
    const token = String(item || '').trim();
    if (token && token.length >= 3) {
      out = out.split(token).join('[redacted]');
    }
  }
  out = out.replace(/postgresql:\/\/\S+/gi, '[redacted-db-url]');
  out = out.replace(/postgres:\/\/\S+/gi, '[redacted-db-url]');
  out = out.replace(/\bep-[a-z0-9-]+(?:\.[a-z0-9-]+)*\.neon\.tech\b/gi, '[redacted-host]');
  out = out.replace(/\bneondb_owner\b/gi, '[redacted-user]');
  out = out.replace(/\bfor user\s+"[^"]+"/gi, 'for user "[redacted]"');
  out = out.replace(/\buser=["']?[^"'\s,;]+["']?/gi, 'user=[redacted]');
  out = out.replace(/\bpassword\s*([:=])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi, 'password$1[redacted]');
  return out;
}

function sanitizePreflightError(err, extraSecrets = []) {
  const raw = err && err.message ? safeError(err) : redactSecrets(String(err || 'unknown error'));
  return sanitizePreflightText(raw, extraSecrets);
}

function assertAllowedPreflightSql(sql) {
  const normalized = String(sql || '').trim();
  if (!ALLOWED_SQL_SET.has(normalized)) {
    throw new Error('Preflight refused SQL statement outside closed allowlist.');
  }
  if (normalized.includes(';')) {
    throw new Error('Preflight refused multi-statement SQL containing ";".');
  }
  const structuralSql = normalized.replace(/'(?:''|[^'])*'/g, "''");
  if (WRITE_OR_DDL_RE.test(structuralSql)) {
    throw new Error('Preflight refused non-read-only SQL keyword.');
  }
  return normalized;
}

function validatePreflightEnvironment(env = process.env, argv = process.argv) {
  const args = Array.isArray(argv) ? argv.slice(2) : [];
  for (const arg of args) {
    if (arg !== '--json') {
      throw new Error(`Unsupported CLI argument "${arg}". Preflight takes no SQL or target arguments.`);
    }
  }

  const appEnv = String((env && env.APP_ENV) || '').trim().toLowerCase();
  if (appEnv !== 'staging') {
    throw new Error(
      `Preflight refused: APP_ENV must be explicitly "staging" (received "${appEnv || 'unset'}").`
    );
  }

  const seedMode = String((env && env.SEED_MODE) || '').trim().toLowerCase();
  if (seedMode !== 'false') {
    throw new Error(
      `Preflight refused: SEED_MODE must be explicitly "false" (received "${seedMode || 'unset'}").`
    );
  }

  if (String((env && env.VERCEL) || '').trim() !== '') {
    throw new Error('Preflight refused: cloud runtime variable VERCEL is set (local execution only).');
  }

  if (String((env && env.VERCEL_ENV) || '').trim() !== '') {
    throw new Error('Preflight refused: cloud runtime variable VERCEL_ENV is set (local execution only).');
  }

  const nodeEnv = String((env && env.NODE_ENV) || '').trim().toLowerCase();
  if (nodeEnv === 'production') {
    throw new Error('Preflight refused: NODE_ENV=production is forbidden.');
  }

  for (const key of ALLOWED_PREFLIGHT_ENV_VARS) {
    if (!String((env && env[key]) || '').trim()) {
      throw new Error(
        `${key} is required for P0.4.5-B preflight. Fallback to ${FORBIDDEN_FALLBACK_VARS.join(', ')} is disabled.`
      );
    }
  }

  return { jsonOutput: args.includes('--json') };
}

function parseAndValidateStagingUrl(rawUrl, varName, expectPooler) {
  const connectionString = String(rawUrl || '').trim();
  if (!connectionString) {
    throw new Error(`${varName} is empty.`);
  }

  let parsed;
  try {
    parsed = new URL(connectionString);
  } catch (_err) {
    throw new Error(`${varName} is not a valid PostgreSQL URI.`);
  }

  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error(`${varName} must use postgres:// or postgresql:// scheme.`);
  }

  const host = String(parsed.hostname || '').trim().toLowerCase();
  if (!host || !host.endsWith('.neon.tech')) {
    throw new Error(`${varName} must point to a Neon (.neon.tech) endpoint.`);
  }

  const labels = host.split('.').filter(Boolean);
  if (labels.length < 4) {
    throw new Error(`${varName} must use a regional Neon endpoint hostname.`);
  }
  const firstLabel = labels[0] || '';
  const regionDomain = labels.slice(1).join('.');
  if (isPoolerHostname(regionDomain)) {
    throw new Error(`${varName} contains unexpected pooler segment in domain path.`);
  }

  let endpointId = '';
  if (expectPooler) {
    if (!isPoolerHostname(host) || !firstLabel.endsWith('-pooler')) {
      throw new Error(`${varName} must use a Neon PgBouncer "-pooler" hostname.`);
    }
    endpointId = firstLabel.slice(0, -'-pooler'.length);
  } else {
    if (isPoolerHostname(host) || firstLabel.endsWith('-pooler')) {
      throw new Error(`${varName} must use a Neon Direct hostname without "-pooler".`);
    }
    endpointId = firstLabel;
  }

  if (!ENDPOINT_ID_RE.test(endpointId) || /(^|-)pooler(-|$)/i.test(endpointId)) {
    throw new Error(`${varName} does not contain a valid Neon endpoint ID in hostname.`);
  }

  let username = '';
  try {
    username = decodeURIComponent(parsed.username || '').trim();
  } catch (_err) {
    throw new Error(`${varName} contains malformed username encoding.`);
  }
  if (!username || username !== EXPECTED_ADMIN_ROLE) {
    throw new Error(`${varName} must authenticate strictly with the expected Neon staging owner role.`);
  }

  if (!String(parsed.password || '').trim()) {
    throw new Error(`${varName} is missing authentication credentials.`);
  }

  const rawPath = String(parsed.pathname || '').replace(/^\/+/, '');
  if (!rawPath || rawPath.includes('/') || /\s/.test(rawPath)) {
    throw new Error(`${varName} must specify single database "neondb" without extra path segments.`);
  }
  let dbName = '';
  try {
    dbName = decodeURIComponent(rawPath);
  } catch (_err) {
    throw new Error(`${varName} contains malformed database path encoding.`);
  }
  if (dbName !== EXPECTED_DATABASE) {
    throw new Error(`${varName} must target database "${EXPECTED_DATABASE}" strictly.`);
  }

  const sslMode = String(parsed.searchParams.get('sslmode') || '').trim().toLowerCase();
  if (sslMode !== 'require') {
    throw new Error(`${varName} must explicitly specify sslmode=require.`);
  }
  for (const unsupportedParam of ['sslcert', 'sslkey', 'sslrootcert']) {
    if (parsed.searchParams.has(unsupportedParam)) {
      throw new Error(`${varName} includes unsupported parameter "${unsupportedParam}".`);
    }
  }

  return {
    varName,
    connectionString,
    host,
    endpointId,
    regionDomain,
    mode: expectPooler ? 'pooled' : 'direct'
  };
}

function validatePreflightTargets(env = process.env, argv = process.argv) {
  const cli = validatePreflightEnvironment(env, argv);

  const expectedEndpointId = String(env.NEON_STAGING_EXPECTED_ENDPOINT_ID || '').trim().toLowerCase();
  if (
    !ENDPOINT_ID_RE.test(expectedEndpointId) ||
    expectedEndpointId.endsWith('-pooler') ||
    /(^|-)pooler(-|$)/i.test(expectedEndpointId)
  ) {
    throw new Error(
      'NEON_STAGING_EXPECTED_ENDPOINT_ID must be a valid bare Neon endpoint ID (e.g. "ep-xxxx-yyyy", without "-pooler").'
    );
  }

  const directTarget = parseAndValidateStagingUrl(env.NEON_STAGING_PREFLIGHT_DIRECT_URL, 'NEON_STAGING_PREFLIGHT_DIRECT_URL', false);
  const pooledTarget = parseAndValidateStagingUrl(env.NEON_STAGING_PREFLIGHT_POOLED_URL, 'NEON_STAGING_PREFLIGHT_POOLED_URL', true);

  if (directTarget.endpointId !== pooledTarget.endpointId) {
    throw new Error('Direct and Pooled endpoint IDs do not match; aborting before connecting.');
  }

  if (directTarget.regionDomain !== pooledTarget.regionDomain) {
    throw new Error('Direct and Pooled endpoints target different Neon regions/domains; aborting before connecting.');
  }

  if (
    directTarget.endpointId !== expectedEndpointId ||
    pooledTarget.endpointId !== expectedEndpointId ||
    directTarget.host !== `${expectedEndpointId}.${directTarget.regionDomain}` ||
    pooledTarget.host !== `${expectedEndpointId}-pooler.${pooledTarget.regionDomain}`
  ) {
    throw new Error(
      'Target endpoints do not match NEON_STAGING_EXPECTED_ENDPOINT_ID; aborting without opening connections.'
    );
  }

  return {
    jsonOutput: cli.jsonOutput,
    expectedEndpointId,
    directTarget,
    pooledTarget
  };
}

async function resolvePoolClass(PoolClass) {
  if (typeof PoolClass === 'function') return PoolClass;
  try {
    const mod = await import('@neondatabase/serverless');
    const Pool = mod.Pool || (mod.default && mod.default.Pool);
    if (typeof Pool !== 'function') throw new Error('Pool export missing');
    return Pool;
  } catch (_err) {
    throw new Error('@neondatabase/serverless is not installed or failed to load. Run "npm install" and retry.');
  }
}

async function runAllowedQuery(client, sql) {
  const verifiedSql = assertAllowedPreflightSql(sql);
  return client.query(verifiedSql);
}

async function executeReadOnlyBlock(target, fn, options = {}) {
  const Pool = await resolvePoolClass(options.PoolClass);
  const pool = new Pool({
    connectionString: target.connectionString,
    max: 1,
    connectionTimeoutMillis: Number(options.connectionTimeoutMillis) > 0 ? Number(options.connectionTimeoutMillis) : 10000,
    idleTimeoutMillis: Number(options.idleTimeoutMillis) > 0 ? Number(options.idleTimeoutMillis) : 5000,
    query_timeout: Number(options.queryTimeoutMs) > 0 ? Number(options.queryTimeoutMs) : 11000
  });

  if (typeof pool.on === 'function') {
    pool.on('error', () => {
      // Captured cleanly in block status without printing raw connection strings.
    });
  }

  let client = null;
  let begun = false;
  let blockErr = null;
  let rollbackFailed = false;
  let rollbackError = null;

  try {
    const tConnect = Date.now();
    client = await pool.connect();
    const connectMs = Date.now() - tConnect;

    await runAllowedQuery(client, PREFLIGHT_SQL.BEGIN_RO);
    begun = true;
    await runAllowedQuery(client, PREFLIGHT_SQL.SET_STATEMENT_TIMEOUT);
    await runAllowedQuery(client, PREFLIGHT_SQL.SET_LOCK_TIMEOUT);
    await runAllowedQuery(client, PREFLIGHT_SQL.SET_IDLE_IN_TX_TIMEOUT);

    const data = await fn(client, { connectMs });
    return {
      ok: true,
      status: 'PASS',
      rollbackFailed: false,
      connectMs,
      data
    };
  } catch (err) {
    blockErr = err;
    throw err;
  } finally {
    let releaseErr = blockErr || null;
    if (client && begun) {
      try {
        await runAllowedQuery(client, PREFLIGHT_SQL.ROLLBACK);
      } catch (rbErr) {
        rollbackFailed = true;
        rollbackError = rbErr;
        releaseErr = rbErr;
      }
    }
    if (client && typeof client.release === 'function') {
      try {
        if (releaseErr) client.release(releaseErr);
        else client.release();
      } catch (_releaseNoise) {
        // Ignore release noise while closing pool.
      }
    }
    try {
      await pool.end();
    } catch (_endNoise) {
      // Ignore shutdown noise.
    }
    if (rollbackFailed) {
      const wrapped = new Error(
        `BLOCKED: ROLLBACK failed in ${target.mode} read-only block (${sanitizePreflightError(rollbackError, [target.connectionString])}). Connection discarded.`
      );
      wrapped.rollbackFailed = true;
      wrapped.originalError = blockErr || null;
      throw wrapped;
    }
  }
}

function parsePgDurationMs(rawValue) {
  const raw = String(rawValue || '').trim().toLowerCase();
  const match = /^(\d+)(ms|s|min)$/.exec(raw);
  if (!match) return null;
  const amount = Number.parseInt(match[1], 10);
  if (match[2] === 'ms') return amount;
  if (match[2] === 's') return amount * 1000;
  if (match[2] === 'min') return amount * 60 * 1000;
  return null;
}

function buildTimeoutCheckResult(row) {
  const statementMs = parsePgDurationMs(row.statement_timeout);
  const lockMs = parsePgDurationMs(row.lock_timeout);
  const idleMs = parsePgDurationMs(row.idle_in_transaction_session_timeout);
  const readOnly = String(row.transaction_read_only || '').trim().toLowerCase() === 'on';

  const pass = statementMs === 8000 && lockMs === 3000 && idleMs === 10000 && readOnly;
  return {
    status: pass ? 'PASS' : 'BLOCKED',
    statementTimeout: row.statement_timeout,
    lockTimeout: row.lock_timeout,
    idleInTransactionSessionTimeout: row.idle_in_transaction_session_timeout,
    transactionReadOnly: row.transaction_read_only,
    matched: {
      statementTimeout8s: statementMs === 8000,
      lockTimeout3s: lockMs === 3000,
      idleInTx10s: idleMs === 10000,
      readOnlyOn: readOnly
    }
  };
}

function evaluateRolesBlock(roleRows, membershipRows, privilegeRows) {
  const rolesByName = new Map();
  for (const row of roleRows || []) {
    rolesByName.set(String(row.rolname), row);
  }

  const adminRow = rolesByName.get(EXPECTED_ADMIN_ROLE) || null;
  const neonSuperRow = rolesByName.get('neon_superuser') || null;
  const privRow = (privilegeRows && privilegeRows[0]) || {};

  const directAttributes = adminRow
    ? {
        rolsuper: Boolean(adminRow.rolsuper),
        rolinherit: Boolean(adminRow.rolinherit),
        rolcreaterole: Boolean(adminRow.rolcreaterole),
        rolcreatedb: Boolean(adminRow.rolcreatedb),
        rolcanlogin: Boolean(adminRow.rolcanlogin),
        rolreplication: Boolean(adminRow.rolreplication),
        rolbypassrls: Boolean(adminRow.rolbypassrls)
      }
    : null;

  const memberships = (membershipRows || []).map((m) => ({
    role: m.role_name,
    memberMatchedExpectedOwner: m.member_name === EXPECTED_ADMIN_ROLE,
    member: m.member_name === EXPECTED_ADMIN_ROLE ? 'expected_owner' : String(m.member_name),
    adminOption: Boolean(m.admin_option),
    inheritOption: m.inherit_option === undefined ? true : Boolean(m.inherit_option),
    setOption: m.set_option === undefined ? true : Boolean(m.set_option)
  }));

  const memberOfNeonSuperuser = Boolean(
    (adminRow && adminRow.member_of_neon_superuser) ||
      memberships.some((m) => m.role === 'neon_superuser' && m.memberMatchedExpectedOwner)
  );
  const effectiveNeonSuperuser = Boolean(
    (adminRow && adminRow.effective_neon_superuser) ||
      (memberOfNeonSuperuser && directAttributes && directAttributes.rolinherit)
  );

  const canCreateRolesEffective = Boolean(
    (directAttributes && directAttributes.rolcreaterole) ||
      (effectiveNeonSuperuser && neonSuperRow && Boolean(neonSuperRow.rolcreaterole))
  );

  const dbOwnerMatchedExpected = Boolean(
    privRow.db_owner === EXPECTED_ADMIN_ROLE || privRow.has_db_owner_role
  );
  const schemaOwnerMatchedExpected = Boolean(
    privRow.schema_owner === EXPECTED_ADMIN_ROLE ||
      (privRow.schema_owner === 'pg_database_owner' && dbOwnerMatchedExpected) ||
      Boolean(privRow.has_schema_owner_role)
  );

  const ownershipAndPrivileges = {
    database: privRow.database_name || EXPECTED_DATABASE,
    dbOwnerMatchedExpected,
    schema: privRow.schema_name || 'public',
    schemaOwnerKind:
      privRow.schema_owner === 'pg_database_owner'
        ? 'pg_database_owner'
        : privRow.schema_owner === EXPECTED_ADMIN_ROLE
          ? 'expected_owner'
          : 'other',
    schemaOwnerMatchedExpected,
    ownerDbConnect: Boolean(privRow.owner_db_connect),
    ownerDbCreate: Boolean(privRow.owner_db_create),
    ownerSchemaUsage: Boolean(privRow.owner_schema_usage),
    ownerSchemaCreate: Boolean(privRow.owner_schema_create),
    publicRoleSchemaCreate: Boolean(privRow.public_schema_create)
  };

  const targetRolesStatus = {};
  for (const roleName of ['arkik_migrator', 'arkik_admin', 'arkik_app']) {
    const r = rolesByName.get(roleName);
    targetRolesStatus[roleName] = r
      ? {
          exists: true,
          rolsuper: Boolean(r.rolsuper),
          rolcreaterole: Boolean(r.rolcreaterole),
          rolcreatedb: Boolean(r.rolcreatedb),
          rolbypassrls: Boolean(r.rolbypassrls)
        }
      : { exists: false };
  }

  const readyForProvisioning =
    Boolean(adminRow) &&
    canCreateRolesEffective &&
    ownershipAndPrivileges.ownerDbConnect &&
    ownershipAndPrivileges.ownerSchemaUsage &&
    ownershipAndPrivileges.ownerSchemaCreate &&
    ownershipAndPrivileges.schemaOwnerMatchedExpected;

  return {
    status: readyForProvisioning ? 'PASS' : 'BLOCKED',
    directAttributes,
    inheritedMemberships: {
      memberOfNeonSuperuser,
      effectiveNeonSuperuser,
      memberships
    },
    effectiveCapabilities: {
      canCreateRolesEffective,
      source: directAttributes && directAttributes.rolcreaterole
        ? 'direct_attribute'
        : effectiveNeonSuperuser
          ? 'inherited_neon_superuser'
          : 'missing'
    },
    ownershipAndPrivileges,
    targetRolesStatus
  };
}

function evaluateInventoryBlock(relationRows, extensionRows, extensionObjectRows) {
  const buckets = {
    tables: [],
    partitionedTables: [],
    sequences: [],
    views: [],
    materializedViews: [],
    foreignTables: []
  };
  const unknownObjects = [];
  const knownArkikObjects = [];

  for (const row of relationRows || []) {
    const item = {
      schema: row.schema_name,
      name: row.object_name,
      type: row.object_type,
      ownerType: row.owner_name === EXPECTED_ADMIN_ROLE ? 'expected_owner' : String(row.owner_name),
      owningExtension: row.owning_extension || null
    };
    if (row.relkind === 'r') buckets.tables.push(item);
    else if (row.relkind === 'p') buckets.partitionedTables.push(item);
    else if (row.relkind === 'S') buckets.sequences.push(item);
    else if (row.relkind === 'v') buckets.views.push(item);
    else if (row.relkind === 'm') buckets.materializedViews.push(item);
    else if (row.relkind === 'f') buckets.foreignTables.push(item);

    if (item.owningExtension) continue;
    if (item.schema === 'public' && KNOWN_ARKIK_RELATIONS.has(item.name)) {
      knownArkikObjects.push(item);
    } else {
      unknownObjects.push(item);
    }
  }

  const extensions = (extensionRows || []).map((e) => ({
    name: e.extension_name,
    version: e.extension_version,
    schema: e.schema_name,
    ownerType: e.owner_name === EXPECTED_ADMIN_ROLE ? 'expected_owner' : String(e.owner_name || '')
  }));

  const extensionObjects = (extensionObjectRows || []).map((d) => ({
    extension: d.extension_name,
    objectClass: d.object_class,
    description: d.object_description
  }));

  const blocked = unknownObjects.length > 0;
  return {
    status: blocked ? 'BLOCKED' : 'PASS',
    blockedReason: blocked ? 'unknown_preexisting_objects_detected' : null,
    virginPublicSchema: knownArkikObjects.length === 0 && unknownObjects.length === 0,
    counts: {
      tables: buckets.tables.length,
      partitionedTables: buckets.partitionedTables.length,
      sequences: buckets.sequences.length,
      views: buckets.views.length,
      materializedViews: buckets.materializedViews.length,
      foreignTables: buckets.foreignTables.length,
      extensions: extensions.length,
      extensionObjects: extensionObjects.length,
      unknownObjects: unknownObjects.length
    },
    relations: buckets,
    knownArkikObjects,
    unknownObjects,
    extensions,
    extensionObjects
  };
}

async function runStagingPreflight(options = {}) {
  const env = options.env || process.env;
  const argv = options.argv || process.argv;
  const targets = validatePreflightTargets(env, argv);
  const blockOptions = {
    PoolClass: options.PoolClass,
    connectionTimeoutMillis: options.connectionTimeoutMillis,
    queryTimeoutMs: options.queryTimeoutMs,
    idleTimeoutMillis: options.idleTimeoutMillis
  };

  const report = {
    verdict: 'BLOCKED',
    endpointId: targets.expectedEndpointId,
    blocks: {}
  };

  let hasBlock = false;
  async function runBlockSafely(key, target, fn) {
    try {
      const outcome = await executeReadOnlyBlock(target, fn, blockOptions);
      report.blocks[key] = outcome.data;
      if (outcome.data && outcome.data.status === 'BLOCKED') hasBlock = true;
    } catch (err) {
      hasBlock = true;
      report.blocks[key] = {
        status: 'BLOCKED',
        rollbackFailed: Boolean(err && err.rollbackFailed),
        error: sanitizePreflightError(err, [targets.directTarget.connectionString, targets.pooledTarget.connectionString])
      };
    }
  }

  // Block A: Direct verification
  await runBlockSafely('direct', targets.directTarget, async (client, meta) => {
    const t0 = Date.now();
    const res = await runAllowedQuery(client, PREFLIGHT_SQL.PROBE_IDENTITY);
    const queryMs = Date.now() - t0;
    const row = (res.rows && res.rows[0]) || {};
    const dbOk = row.current_database === EXPECTED_DATABASE;
    const userOk = row.current_user === EXPECTED_ADMIN_ROLE;
    return {
      status: dbOk && userOk ? 'PASS' : 'BLOCKED',
      mode: 'direct',
      endpointId: targets.directTarget.endpointId,
      database: row.current_database || null,
      expectedUserMatched: userOk,
      sessionMatchesCurrentUser: row.session_user === row.current_user,
      serverVersion: row.server_version || null,
      serverVersionNum: Number(row.server_version_num || 0),
      connectMs: meta.connectMs,
      queryMs
    };
  });

  // Block B: Pooled verification
  await runBlockSafely('pooled', targets.pooledTarget, async (client, meta) => {
    const t0 = Date.now();
    const res = await runAllowedQuery(client, PREFLIGHT_SQL.PROBE_IDENTITY);
    const queryMs = Date.now() - t0;
    const row = (res.rows && res.rows[0]) || {};
    const dbOk = row.current_database === EXPECTED_DATABASE;
    const userOk = row.current_user === EXPECTED_ADMIN_ROLE;
    return {
      status: dbOk && userOk ? 'PASS' : 'BLOCKED',
      mode: 'pooled',
      endpointId: targets.pooledTarget.endpointId,
      database: row.current_database || null,
      expectedUserMatched: userOk,
      connectMs: meta.connectMs,
      queryMs
    };
  });

  // Block C: Transactional SET LOCAL timeouts on Direct and Pooled
  await runBlockSafely('timeoutsDirect', targets.directTarget, async (client) => {
    const res = await runAllowedQuery(client, PREFLIGHT_SQL.READ_TIMEOUT_SETTINGS);
    return buildTimeoutCheckResult((res.rows && res.rows[0]) || {});
  });
  await runBlockSafely('timeoutsPooled', targets.pooledTarget, async (client) => {
    const res = await runAllowedQuery(client, PREFLIGHT_SQL.READ_TIMEOUT_SETTINGS);
    return buildTimeoutCheckResult((res.rows && res.rows[0]) || {});
  });

  // Block D: Role attributes, neon_superuser inheritance & schema ownership/privileges
  await runBlockSafely('roles', targets.directTarget, async (client) => {
    const rolesRes = await runAllowedQuery(client, PREFLIGHT_SQL.INSPECT_ROLES);
    const membersRes = await runAllowedQuery(client, PREFLIGHT_SQL.INSPECT_ROLE_MEMBERSHIPS);
    const privsRes = await runAllowedQuery(client, PREFLIGHT_SQL.INSPECT_DB_AND_SCHEMA_PRIVILEGES);
    return evaluateRolesBlock(rolesRes.rows, membersRes.rows, privsRes.rows);
  });

  // Block E: Pre-existing object inventory
  await runBlockSafely('inventory', targets.directTarget, async (client) => {
    const relRes = await runAllowedQuery(client, PREFLIGHT_SQL.INVENTORY_RELATIONS);
    const extRes = await runAllowedQuery(client, PREFLIGHT_SQL.INVENTORY_EXTENSIONS);
    const extObjRes = await runAllowedQuery(client, PREFLIGHT_SQL.INVENTORY_EXTENSION_OBJECTS);
    return evaluateInventoryBlock(relRes.rows, extRes.rows, extObjRes.rows);
  });

  report.verdict = hasBlock ? 'BLOCKED' : 'READY';
  return report;
}

if (require.main === module) {
  loadEnvFiles();
  runStagingPreflight()
    .then((report) => {
      console.log(JSON.stringify(report, null, 2));
      if (report.verdict !== 'READY') process.exitCode = 2;
    })
    .catch((err) => {
      console.error(`[ARKIK PREFLIGHT] BLOCKED: ${sanitizePreflightError(err)}`);
      process.exitCode = 1;
    });
}

module.exports = {
  ALLOWED_PREFLIGHT_ENV_VARS,
  FORBIDDEN_FALLBACK_VARS,
  EXPECTED_ADMIN_ROLE,
  EXPECTED_DATABASE,
  KNOWN_ARKIK_RELATIONS,
  PREFLIGHT_SQL,
  sanitizePreflightError,
  assertAllowedPreflightSql,
  validatePreflightEnvironment,
  parseAndValidateStagingUrl,
  validatePreflightTargets,
  executeReadOnlyBlock,
  buildTimeoutCheckResult,
  evaluateRolesBlock,
  evaluateInventoryBlock,
  runStagingPreflight
};
