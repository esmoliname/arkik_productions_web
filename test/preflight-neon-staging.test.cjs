'use strict';
// Offline unit & invariant tests for P0.4.5-B1 read-only Neon STAGING preflight.
// Zero network connections, zero real DB queries, zero secret exposure.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const preflight = require(path.join(REPO, 'scripts', 'preflight-neon-staging.js'));

const STAGING_EP = 'ep-staging-arkik-123456';
const PROD_EP = 'ep-prod-arkik-999999';
const SECRET_PW = 'Preflight_Secret_Pw_987654';
const DIRECT_URL = `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/neondb?sslmode=require`;
const POOLED_URL = `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`;

function baseStagingEnv(overrides = {}) {
  return Object.assign(
    {
      APP_ENV: 'staging',
      SEED_MODE: 'false',
      NODE_ENV: 'development',
      NEON_STAGING_EXPECTED_ENDPOINT_ID: STAGING_EP,
      NEON_STAGING_PREFLIGHT_DIRECT_URL: DIRECT_URL,
      NEON_STAGING_PREFLIGHT_POOLED_URL: POOLED_URL
    },
    overrides
  );
}

describe('P0.4.5-B1 Read-Only Neon STAGING Preflight Suite (Offline Mocks)', () => {
  test('P1: Aborts BEFORE opening any connection when endpoint ID mismatches (Production protection) or endpoints diverge', async () => {
    let poolInstantiations = 0;
    class FailIfConstructedPool {
      constructor() {
        poolInstantiations += 1;
      }
    }

    await assert.rejects(
      () =>
        preflight.runStagingPreflight({
          env: baseStagingEnv({ NEON_STAGING_EXPECTED_ENDPOINT_ID: PROD_EP }),
          argv: ['node', 'scripts/preflight-neon-staging.js'],
          PoolClass: FailIfConstructedPool
        }),
      /do not match NEON_STAGING_EXPECTED_ENDPOINT_ID/
    );

    await assert.rejects(
      () =>
        preflight.runStagingPreflight({
          env: baseStagingEnv({
            NEON_STAGING_PREFLIGHT_POOLED_URL: `postgresql://neondb_owner:${SECRET_PW}@${PROD_EP}-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`
          }),
          argv: ['node', 'scripts/preflight-neon-staging.js'],
          PoolClass: FailIfConstructedPool
        }),
      /do not match; aborting before connecting/
    );

    await assert.rejects(
      () =>
        preflight.runStagingPreflight({
          env: baseStagingEnv({
            NEON_STAGING_PREFLIGHT_POOLED_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require`
          }),
          argv: ['node', 'scripts/preflight-neon-staging.js'],
          PoolClass: FailIfConstructedPool
        }),
      /different Neon regions/
    );

    assert.equal(poolInstantiations, 0, 'Production/mismatch checks must abort before constructing any Pool');
  });

  test('P2: Rejects -pooler in Direct, missing -pooler in Pooled, wrong user/db/SSL, missing vars, cloud/Vercel env & fallbacks', () => {
    const cases = [
      [{ NEON_STAGING_PREFLIGHT_DIRECT_URL: POOLED_URL }, /Direct hostname without "-pooler"/],
      [{ NEON_STAGING_PREFLIGHT_POOLED_URL: DIRECT_URL }, /PgBouncer "-pooler" hostname/],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://wrong_user:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/neondb?sslmode=require`
        },
        /expected Neon staging owner role/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/production?sslmode=require`
        },
        /must target database "neondb"/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/neondb/extra?sslmode=require`
        },
        /single database "neondb"/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/neondb?sslmode=disable`
        },
        /sslmode=require/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_POOLED_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}-pooler.us-east-2.aws.neon.tech/neondb?sslmode=prefer`
        },
        /sslmode=require/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.us-east-2.aws.neon.tech/neondb?sslmode=require&sslrootcert=/tmp/ca.pem`
        },
        /unsupported parameter "sslrootcert"/
      ],
      [{ VERCEL: '1' }, /VERCEL is set/],
      [{ VERCEL_ENV: 'preview' }, /VERCEL_ENV is set/],
      [{ NODE_ENV: 'production' }, /NODE_ENV=production is forbidden/],
      [{ APP_ENV: 'development' }, /APP_ENV must be explicitly "staging"/],
      [{ APP_ENV: 'production' }, /APP_ENV must be explicitly "staging"/],
      [{ SEED_MODE: 'true' }, /SEED_MODE must be explicitly "false"/],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: '',
          DATABASE_URL: POOLED_URL,
          DIRECT_DATABASE_URL: DIRECT_URL,
          DIRECT_ADMIN_DATABASE_URL: DIRECT_URL
        },
        /NEON_STAGING_PREFLIGHT_DIRECT_URL is required.*Fallback to DATABASE_URL, DIRECT_DATABASE_URL, DIRECT_ADMIN_DATABASE_URL is disabled/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_POOLED_URL: '',
          DATABASE_URL: POOLED_URL,
          DIRECT_DATABASE_URL: DIRECT_URL,
          DIRECT_ADMIN_DATABASE_URL: DIRECT_URL
        },
        /NEON_STAGING_PREFLIGHT_POOLED_URL is required/
      ],
      [{ NEON_STAGING_EXPECTED_ENDPOINT_ID: '' }, /NEON_STAGING_EXPECTED_ENDPOINT_ID is required/]
    ];

    for (const [overrides, expectedRe] of cases) {
      let caught = null;
      try {
        preflight.validatePreflightTargets(baseStagingEnv(overrides), ['node', 'scripts/preflight-neon-staging.js']);
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, `expected rejection for overrides ${Object.keys(overrides).join(',')}`);
      assert.match(caught.message, expectedRe);
      assert.equal(caught.message.includes(SECRET_PW), false, 'error must not leak password');
      assert.equal(caught.message.includes('wrong_user'), false, 'error must not leak rejected username');
      assert.equal(caught.message.includes('postgresql://'), false, 'error must not leak raw URI');
    }

    assert.throws(
      () => preflight.validatePreflightTargets(baseStagingEnv(), ['node', 'scripts/preflight-neon-staging.js', 'DELETE FROM bookings']),
      /Unsupported CLI argument/
    );
  });

  test('P3: Enforces exact BEGIN READ ONLY -> SET LOCAL -> SELECT -> ROLLBACK order, releases client, closes pool, and handles inherited neon_superuser attributes', async () => {
    const traces = [];

    class FakePreflightPool {
      constructor(opts) {
        const trace = {
          mode: opts.connectionString.includes('-pooler.') ? 'pooled' : 'direct',
          queries: [],
          releaseArgs: [],
          ended: false
        };
        traces.push(trace);
        this.trace = trace;
      }
      on() {}
      async connect() {
        const trace = this.trace;
        return {
          async query(sql) {
            const text = String(sql).trim();
            trace.queries.push(text);
            if (text === preflight.PREFLIGHT_SQL.PROBE_IDENTITY) {
              return {
                rows: [
                  {
                    current_database: 'neondb',
                    current_user: 'neondb_owner',
                    session_user: 'neondb_owner',
                    server_version: '18.7',
                    server_version_num: 180007
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.READ_TIMEOUT_SETTINGS) {
              return {
                rows: [
                  {
                    statement_timeout: '8s',
                    lock_timeout: '3s',
                    idle_in_transaction_session_timeout: '10s',
                    transaction_read_only: 'on'
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INSPECT_ROLES) {
              return {
                rows: [
                  {
                    rolname: 'neon_superuser',
                    rolsuper: false,
                    rolinherit: true,
                    rolcreaterole: true,
                    rolcreatedb: true,
                    rolcanlogin: false,
                    rolreplication: false,
                    rolbypassrls: true,
                    member_of_neon_superuser: false,
                    effective_neon_superuser: false
                  },
                  {
                    // Deliberately rolcreaterole=false directly, inheriting capability from neon_superuser
                    rolname: 'neondb_owner',
                    rolsuper: false,
                    rolinherit: true,
                    rolcreaterole: false,
                    rolcreatedb: false,
                    rolcanlogin: true,
                    rolreplication: false,
                    rolbypassrls: false,
                    member_of_neon_superuser: true,
                    effective_neon_superuser: true
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INSPECT_ROLE_MEMBERSHIPS) {
              return {
                rows: [
                  {
                    role_name: 'neon_superuser',
                    member_name: 'neondb_owner',
                    grantor_name: 'cloud_admin',
                    admin_option: false,
                    inherit_option: true,
                    set_option: true
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INSPECT_DB_AND_SCHEMA_PRIVILEGES) {
              return {
                rows: [
                  {
                    database_name: 'neondb',
                    db_owner: 'neondb_owner',
                    schema_name: 'public',
                    schema_owner: 'neondb_owner',
                    owner_db_connect: true,
                    owner_db_create: true,
                    owner_schema_usage: true,
                    owner_schema_create: true,
                    public_schema_create: false
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INVENTORY_RELATIONS) {
              return {
                rows: [
                  // Extension-owned view (e.g., pg_stat_statements) must not falsely block virgin DB check
                  {
                    schema_name: 'public',
                    object_name: 'pg_stat_statements',
                    relkind: 'v',
                    object_type: 'view',
                    owner_name: 'cloud_admin',
                    owning_extension: 'pg_stat_statements'
                  }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INVENTORY_EXTENSIONS) {
              return {
                rows: [
                  { extension_name: 'plpgsql', extension_version: '1.0', schema_name: 'pg_catalog', owner_name: 'cloud_admin' },
                  { extension_name: 'pg_stat_statements', extension_version: '1.11', schema_name: 'public', owner_name: 'cloud_admin' }
                ]
              };
            }
            if (text === preflight.PREFLIGHT_SQL.INVENTORY_EXTENSION_OBJECTS) {
              return {
                rows: [
                  {
                    extension_name: 'pg_stat_statements',
                    object_class: 'pg_class',
                    object_description: 'view pg_stat_statements'
                  }
                ]
              };
            }
            return { rows: [] };
          },
          release(arg) {
            trace.releaseArgs.push(arg === undefined ? null : arg);
          }
        };
      }
      async end() {
        this.trace.ended = true;
      }
    }

    const report = await preflight.runStagingPreflight({
      env: baseStagingEnv(),
      argv: ['node', 'scripts/preflight-neon-staging.js'],
      PoolClass: FakePreflightPool
    });

    assert.equal(report.verdict, 'READY');
    assert.equal(report.endpointId, STAGING_EP);
    assert.equal(report.blocks.direct.status, 'PASS');
    assert.equal(report.blocks.pooled.status, 'PASS');
    assert.equal(report.blocks.timeoutsDirect.status, 'PASS');
    assert.equal(report.blocks.timeoutsPooled.status, 'PASS');
    assert.equal(report.blocks.roles.status, 'PASS');
    assert.equal(report.blocks.roles.directAttributes.rolcreaterole, false);
    assert.equal(report.blocks.roles.effectiveCapabilities.canCreateRolesEffective, true);
    assert.equal(report.blocks.roles.effectiveCapabilities.source, 'inherited_neon_superuser');
    assert.equal(report.blocks.inventory.status, 'PASS');
    assert.equal(report.blocks.inventory.virginPublicSchema, true);
    assert.equal(traces.length, 6);

    for (const trace of traces) {
      assert.equal(trace.queries[0], 'BEGIN READ ONLY');
      assert.equal(trace.queries[1], 'SET LOCAL statement_timeout = 8000');
      assert.equal(trace.queries[2], 'SET LOCAL lock_timeout = 3000');
      assert.equal(trace.queries[3], 'SET LOCAL idle_in_transaction_session_timeout = 10000');
      assert.equal(trace.queries[trace.queries.length - 1], 'ROLLBACK');
      for (const q of trace.queries) {
        assert.equal(q.includes(';'), false, 'must never concatenate SQL statements');
      }
      assert.deepEqual(trace.releaseArgs, [null]);
      assert.equal(trace.ended, true);
    }

    const serialized = JSON.stringify(report);
    assert.equal(serialized.includes(SECRET_PW), false);
    assert.equal(serialized.includes('neondb_owner'), false, 'output must not print DB username verbatim');
    assert.equal(serialized.includes('postgresql://'), false);
  });

  test('P4: Executes ROLLBACK on SELECT failure; marks BLOCKED and discards client on ROLLBACK failure', async () => {
    // 1. SELECT fails -> ROLLBACK still executes and client + pool close cleanly
    let selectErrTrace = null;
    class SelectFailPool {
      constructor() {
        selectErrTrace = { queries: [], releaseArgs: [], ended: false };
      }
      on() {}
      async connect() {
        return {
          async query(sql) {
            selectErrTrace.queries.push(sql);
            if (sql.startsWith('SELECT')) {
              throw new Error(`boom for user "neondb_owner" ${DIRECT_URL}`);
            }
            return { rows: [] };
          },
          release(err) {
            selectErrTrace.releaseArgs.push(err || null);
          }
        };
      }
      async end() {
        selectErrTrace.ended = true;
      }
    }

    await assert.rejects(
      () =>
        preflight.executeReadOnlyBlock(
          { connectionString: DIRECT_URL, mode: 'direct' },
          (client) => client.query(preflight.PREFLIGHT_SQL.PROBE_IDENTITY),
          { PoolClass: SelectFailPool }
        ),
      /boom/
    );
    assert.equal(selectErrTrace.queries[0], 'BEGIN READ ONLY');
    assert.equal(selectErrTrace.queries[selectErrTrace.queries.length - 1], 'ROLLBACK');
    assert.ok(selectErrTrace.releaseArgs[0] instanceof Error, 'failed block must discard client');
    assert.equal(selectErrTrace.ended, true);

    // 2. ROLLBACK fails -> BLOCKED, discards connection with rollback Error, never returns reusable to pool
    let rbTrace = null;
    class RollbackFailPool {
      constructor() {
        rbTrace = { releaseArgs: [], ended: false };
      }
      on() {}
      async connect() {
        return {
          async query(sql) {
            if (sql === 'ROLLBACK') {
              throw new Error(`rollback failed for ${DIRECT_URL}`);
            }
            if (sql === preflight.PREFLIGHT_SQL.PROBE_IDENTITY) {
              return { rows: [{ current_database: 'neondb', current_user: 'neondb_owner' }] };
            }
            return { rows: [] };
          },
          release(err) {
            rbTrace.releaseArgs.push(err || null);
          }
        };
      }
      async end() {
        rbTrace.ended = true;
      }
    }

    const report = await preflight.runStagingPreflight({
      env: baseStagingEnv(),
      argv: ['node', 'scripts/preflight-neon-staging.js'],
      PoolClass: RollbackFailPool
    });

    assert.equal(report.verdict, 'BLOCKED');
    assert.equal(report.blocks.direct.status, 'BLOCKED');
    assert.equal(report.blocks.direct.rollbackFailed, true);
    assert.equal(report.blocks.direct.error.includes(SECRET_PW), false);
    assert.equal(report.blocks.direct.error.includes('neondb_owner'), false);
    assert.ok(rbTrace.releaseArgs[0] instanceof Error, 'failed ROLLBACK must discard client via release(err)');
    assert.equal(rbTrace.ended, true);
  });

  test('P5: Block E marks BLOCKED when unknown preexisting tables, partitioned tables, sequences, views, matviews or foreign tables exist', () => {
    const dirtyInventory = preflight.evaluateInventoryBlock(
      [
        {
          schema_name: 'public',
          object_name: 'legacy_users',
          relkind: 'r',
          object_type: 'table',
          owner_name: 'neondb_owner',
          owning_extension: null
        },
        {
          schema_name: 'public',
          object_name: 'ext_audit_part',
          relkind: 'p',
          object_type: 'partitioned_table',
          owner_name: 'neondb_owner',
          owning_extension: null
        },
        {
          schema_name: 'analytics',
          object_name: 'remote_events_fdw',
          relkind: 'f',
          object_type: 'foreign_table',
          owner_name: 'neondb_owner',
          owning_extension: null
        }
      ],
      [],
      []
    );

    assert.equal(dirtyInventory.status, 'BLOCKED');
    assert.equal(dirtyInventory.blockedReason, 'unknown_preexisting_objects_detected');
    assert.equal(dirtyInventory.counts.unknownObjects, 3);
    assert.equal(dirtyInventory.counts.tables, 1);
    assert.equal(dirtyInventory.counts.partitionedTables, 1);
    assert.equal(dirtyInventory.counts.foreignTables, 1);
  });

  test('P6: Closed SQL allowlist contains zero writes/concatenation and runtime bundles isolate NEON_STAGING_PREFLIGHT_*', () => {
    const sqlStatements = Object.values(preflight.PREFLIGHT_SQL);
    assert.ok(sqlStatements.length >= 10);
    for (const sql of sqlStatements) {
      assert.equal(preflight.assertAllowedPreflightSql(sql), sql);
    }

    assert.throws(
      () => preflight.assertAllowedPreflightSql('INSERT INTO audit_log(action) VALUES ($1)'),
      /outside closed allowlist/
    );
    assert.throws(
      () => preflight.assertAllowedPreflightSql('SELECT 1; DROP TABLE bookings'),
      /outside closed allowlist/
    );

    const scriptSrc = fs.readFileSync(path.join(REPO, 'scripts', 'preflight-neon-staging.js'), 'utf8');
    assert.equal(/writeFileSync\(['"]?\.env\.local/i.test(scriptSrc), false);

    const sanitized = preflight.sanitizePreflightError(
      new Error(`auth fail for user "neondb_owner" on ${DIRECT_URL} user=neondb_owner`),
      [DIRECT_URL, SECRET_PW, 'neondb_owner']
    );
    assert.equal(sanitized.includes(SECRET_PW), false);
    assert.equal(sanitized.includes('neondb_owner'), false);
    assert.equal(sanitized.includes('postgresql://'), false);

    for (const rootDir of ['api', 'js']) {
      const stack = [path.join(REPO, rootDir)];
      while (stack.length) {
        const cur = stack.pop();
        for (const ent of fs.readdirSync(cur, { withFileTypes: true })) {
          const full = path.join(cur, ent.name);
          if (ent.isDirectory()) stack.push(full);
          else if (ent.isFile() && ent.name.endsWith('.js')) {
            const src = fs.readFileSync(full, 'utf8');
            assert.equal(/NEON_STAGING_PREFLIGHT_|NEON_STAGING_EXPECTED_ENDPOINT_ID/.test(src), false, `leak in ${full}`);
          }
        }
      }
    }
  });

  test('P7: Rejects partial/prefix/suffix endpoint ID collisions, subdomain tricks & pooler smuggling before Pool instantiation', async () => {
    let poolInstantiations = 0;
    class NeverPool {
      constructor() {
        poolInstantiations += 1;
      }
    }

    const partialAndMaliciousCases = [
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}-extra.us-east-2.aws.neon.tech/neondb?sslmode=require`
        },
        /do not match/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@my-${STAGING_EP}.us-east-2.aws.neon.tech/neondb?sslmode=require`
        },
        /valid Neon endpoint ID/
      ],
      [
        {
          NEON_STAGING_EXPECTED_ENDPOINT_ID: `${STAGING_EP}-pooler`
        },
        /bare Neon endpoint ID/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@ep-pooler-staging-123.us-east-2.aws.neon.tech/neondb?sslmode=require`,
          NEON_STAGING_PREFLIGHT_POOLED_URL: `postgresql://neondb_owner:${SECRET_PW}@ep-pooler-staging-123-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
          NEON_STAGING_EXPECTED_ENDPOINT_ID: 'ep-pooler-staging-123'
        },
        /bare Neon endpoint ID|valid Neon endpoint ID/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.pooler.aws.neon.tech/neondb?sslmode=require`
        },
        /unexpected pooler segment|without "-pooler"/
      ],
      [
        {
          NEON_STAGING_PREFLIGHT_DIRECT_URL: `postgresql://neondb_owner:${SECRET_PW}@${STAGING_EP}.neon.tech/neondb?sslmode=require`
        },
        /regional Neon endpoint hostname/
      ]
    ];

    for (const [overrides, expectedRe] of partialAndMaliciousCases) {
      let caught = null;
      try {
        await preflight.runStagingPreflight({
          env: baseStagingEnv(overrides),
          argv: ['node', 'scripts/preflight-neon-staging.js'],
          PoolClass: NeverPool
        });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, `expected rejection for overrides ${Object.keys(overrides).join(',')}`);
      assert.match(caught.message, expectedRe);
      assert.equal(caught.message.includes(SECRET_PW), false);
    }

    assert.equal(poolInstantiations, 0);
  });

  test('P8: PostgreSQL 18 pg_database_owner compatibility, missing inherited rolcreaterole rejection, catalog SQL invariants & intrinsic error redaction', () => {
    // 1. PG 15+/18 default: schema public owned by pg_database_owner passes when owner has db/schema owner role
    const pg18Roles = preflight.evaluateRolesBlock(
      [
        {
          rolname: 'neon_superuser',
          rolsuper: false,
          rolinherit: true,
          rolcreaterole: true,
          rolcreatedb: true,
          rolcanlogin: false,
          rolreplication: false,
          rolbypassrls: true,
          member_of_neon_superuser: false,
          effective_neon_superuser: false
        },
        {
          rolname: 'neondb_owner',
          rolsuper: false,
          rolinherit: true,
          rolcreaterole: false,
          rolcreatedb: false,
          rolcanlogin: true,
          rolreplication: false,
          rolbypassrls: false,
          member_of_neon_superuser: true,
          effective_neon_superuser: true
        }
      ],
      [{ role_name: 'neon_superuser', member_name: 'neondb_owner', grantor_name: 'cloud_admin', admin_option: false, inherit_option: true, set_option: true }],
      [
        {
          database_name: 'neondb',
          db_owner: 'neondb_owner',
          schema_name: 'public',
          schema_owner: 'pg_database_owner',
          has_db_owner_role: true,
          has_schema_owner_role: true,
          owner_db_connect: true,
          owner_db_create: true,
          owner_schema_usage: true,
          owner_schema_create: true,
          public_schema_create: false
        }
      ]
    );
    assert.equal(pg18Roles.status, 'PASS');
    assert.equal(pg18Roles.ownershipAndPrivileges.schemaOwnerKind, 'pg_database_owner');
    assert.equal(pg18Roles.ownershipAndPrivileges.schemaOwnerMatchedExpected, true);

    // 2. If neon_superuser also lacked rolcreaterole and neondb_owner lacks direct rolcreaterole, BLOCKED
    const deniedRoles = preflight.evaluateRolesBlock(
      [
        { rolname: 'neon_superuser', rolsuper: false, rolinherit: true, rolcreaterole: false, rolcreatedb: false, rolcanlogin: false },
        { rolname: 'neondb_owner', rolsuper: false, rolinherit: true, rolcreaterole: false, rolcreatedb: false, rolcanlogin: true, member_of_neon_superuser: true, effective_neon_superuser: true }
      ],
      [],
      [
        {
          database_name: 'neondb',
          db_owner: 'neondb_owner',
          schema_name: 'public',
          schema_owner: 'pg_database_owner',
          has_db_owner_role: true,
          has_schema_owner_role: true,
          owner_db_connect: true,
          owner_db_create: true,
          owner_schema_usage: true,
          owner_schema_create: true,
          public_schema_create: false
        }
      ]
    );
    assert.equal(deniedRoles.status, 'BLOCKED');
    assert.equal(deniedRoles.effectiveCapabilities.canCreateRolesEffective, false);

    // 3. Verify PG 18 SQL catalog & anti-false-positive filters
    assert.match(preflight.PREFLIGHT_SQL.INSPECT_ROLE_MEMBERSHIPS, /LEFT JOIN pg_roles grantor_r/i);
    assert.match(preflight.PREFLIGHT_SQL.INVENTORY_RELATIONS, /\^pg_\(toast\|temp\)/);
    assert.match(preflight.PREFLIGHT_SQL.INVENTORY_RELATIONS, /dep\.refclassid = 'pg_extension'::regclass/);
    assert.match(preflight.PREFLIGHT_SQL.INVENTORY_EXTENSION_OBJECTS, /d\.refclassid = 'pg_extension'::regclass/);

    // 4. Intrinsic error sanitization without passing extraSecrets still scrubs user, host, password & URI
    const intrinsicSanitized = preflight.sanitizePreflightError(
      new Error(`connect failed for neondb_owner at ${STAGING_EP}.us-east-2.aws.neon.tech password=secret_raw_123`)
    );
    assert.equal(intrinsicSanitized.includes('neondb_owner'), false);
    assert.equal(intrinsicSanitized.includes(STAGING_EP), false);
    assert.equal(intrinsicSanitized.includes('secret_raw_123'), false);
  });
});
