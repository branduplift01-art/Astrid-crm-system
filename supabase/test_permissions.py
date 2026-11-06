"""Run the CRM permission migration against a throwaway Postgres that mimics Supabase auth."""
import json, sys, tempfile, datetime
import pgserver, psycopg2

MIGRATION = sys.argv[1]
ADMIN = '00000000-0000-0000-0000-00000000000a'
USER = '00000000-0000-0000-0000-00000000000b'
STRANGER = '00000000-0000-0000-0000-00000000000c'

srv = pgserver.get_server(tempfile.mkdtemp(), cleanup_mode='stop')
conn = psycopg2.connect(srv.get_uri())
conn.autocommit = True
cur = conn.cursor()

# --- Supabase-like scaffolding + the ORIGINAL schema from SUPABASE_SETUP.md ---
cur.execute(f"""
CREATE ROLE authenticated NOLOGIN;
CREATE SCHEMA auth;
CREATE TABLE auth.users (id uuid PRIMARY KEY, email text);
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT EXECUTE ON FUNCTION auth.uid() TO authenticated;

CREATE TABLE app_data (key TEXT PRIMARY KEY, value JSONB, updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE user_profiles (id UUID REFERENCES auth.users PRIMARY KEY, role TEXT DEFAULT 'user', display_name TEXT);
ALTER TABLE app_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth_read_app_data" ON app_data FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_write_app_data" ON app_data FOR ALL TO authenticated USING (true);
CREATE POLICY "auth_read_profiles" ON user_profiles FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_update_own_profile" ON user_profiles FOR UPDATE TO authenticated USING (auth.uid() = id);
GRANT ALL ON app_data, user_profiles TO authenticated;

INSERT INTO auth.users VALUES ('{ADMIN}','a@x'),('{USER}','u@x'),('{STRANGER}','s@x');
INSERT INTO user_profiles VALUES ('{ADMIN}','admin','管理者'),('{USER}','user','業務');
""")

today = datetime.date.today()
fresh = today.isoformat()
old = (today - datetime.timedelta(days=40)).isoformat()

def seed():
    cur.execute("RESET ROLE; DELETE FROM app_data;")
    rows = {
        'settings': {'rates': {'usdTwd': 30.5}},
        'crm': [{'id': 1, 'name': 'A'}, {'id': 2, 'name': 'B'}],
        'orders': [{'id': 10, 'customerId': 1}],
        'trash': {'customers': [{'id': 3, 'name': 'C', 'deletedAt': fresh},
                                {'id': 4, 'name': 'D', 'deletedAt': old}],
                  'orders': [{'id': 11, 'deletedAt': fresh}]},
    }
    for k, v in rows.items():
        cur.execute("INSERT INTO app_data(key,value) VALUES (%s,%s)", (k, json.dumps(v)))

def as_user(uid, sql, params=()):
    """Run sql as the 'authenticated' role with auth.uid() = uid. Returns (ok, rowcount|error)."""
    try:
        cur.execute("RESET ROLE")
        cur.execute("SELECT set_config('request.jwt.claim.sub', %s, false)", (uid,))
        cur.execute("SET ROLE authenticated")
        cur.execute(sql, params)
        return True, cur.rowcount
    except psycopg2.Error as e:
        return False, e.pgerror.strip().splitlines()[0]
    finally:
        cur.execute("RESET ROLE")

def upsert(uid, key, value):  # same shape supabase-js .upsert(..., {onConflict:'key'}) produces
    return as_user(uid, "INSERT INTO app_data(key,value) VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                   (key, json.dumps(value)))

results = []
def check(name, got, expect_ok, expect_rows=None):
    ok, info = got
    passed = ok == expect_ok and (expect_rows is None or info == expect_rows)
    results.append(passed)
    print(('PASS' if passed else 'FAIL'), name, '->', info)

# Prove the hole exists BEFORE the migration
seed()
check('[before] user deletes customer via upsert', upsert(USER, 'crm', [{'id': 1}]), True)
check('[before] user promotes self to admin', as_user(USER, "UPDATE user_profiles SET role='admin' WHERE id=%s", (USER,)), True, 1)
cur.execute("UPDATE user_profiles SET role='user' WHERE id=%s", (USER,))

# Apply migration twice (must be re-runnable)
sql = open(MIGRATION, encoding='utf-8').read()
cur.execute(sql); cur.execute(sql)
print('migration applied twice OK')

seed()
check('stranger (no profile) sees no data', as_user(STRANGER, "SELECT * FROM app_data"), True, 0)
check('stranger cannot write', upsert(STRANGER, 'tools', []), False)
check('user reads all rows', as_user(USER, "SELECT * FROM app_data"), True, 4)
check('user cannot change settings', upsert(USER, 'settings', {'rates': {'usdTwd': 1}}), False)
check('admin can change settings', upsert(ADMIN, 'settings', {'rates': {'usdTwd': 31}}), True)
check('user can write tools', upsert(USER, 'tools', {'links': []}), True)
check('user adds a customer', upsert(USER, 'crm', [{'id': 1}, {'id': 2}, {'id': 5}]), True)
check('user edits a customer', upsert(USER, 'crm', [{'id': 1, 'name': 'A2'}, {'id': 2}, {'id': 5}]), True)
check('user cannot remove customer', upsert(USER, 'crm', [{'id': 1}, {'id': 5}]), False)
check('user cannot wipe customers', upsert(USER, 'crm', []), False)
check('user cannot remove order', upsert(USER, 'orders', []), False)
check('stale save that drops a colleague\'s new customer is blocked', upsert(USER, 'crm', [{'id': 1}, {'id': 2}]), False)
check('admin can remove customer', upsert(ADMIN, 'crm', [{'id': 1}, {'id': 2}]), True)
check('user DELETE row affects nothing', as_user(USER, "DELETE FROM app_data WHERE key='crm'"), True, 0)
check('admin DELETE row works', as_user(ADMIN, "DELETE FROM app_data WHERE key='tools'"), True, 1)

seed()
trash_no_c3 = {'customers': [{'id': 4, 'deletedAt': old}], 'orders': [{'id': 11, 'deletedAt': fresh}]}
check('user cannot permanently delete fresh trash item', upsert(USER, 'trash', trash_no_c3), False)
check('user may purge expired trash item', upsert(USER, 'trash',
      {'customers': [{'id': 3, 'deletedAt': fresh}], 'orders': [{'id': 11, 'deletedAt': fresh}]}), True)
seed()
check('restore step 1: user saves crm with restored customer', upsert(USER, 'crm', [{'id': 3}, {'id': 1}, {'id': 2}]), True)
check('restore step 2: user removes it from trash', upsert(USER, 'trash', trash_no_c3), True)
seed()
check('user cannot restore-by-trash-only (order not back in list)', upsert(USER, 'trash',
      {'customers': [{'id': 3, 'deletedAt': fresh}, {'id': 4, 'deletedAt': old}], 'orders': []}), False)
check('admin can permanently delete fresh trash', upsert(ADMIN, 'trash', trash_no_c3), True)

check('user cannot promote self', as_user(USER, "UPDATE user_profiles SET role='admin' WHERE id=%s", (USER,)), False)
check('user can rename self', as_user(USER, "UPDATE user_profiles SET display_name='新名字' WHERE id=%s", (USER,)), True, 1)
check('user cannot edit another profile', as_user(USER, "UPDATE user_profiles SET display_name='x' WHERE id=%s", (ADMIN,)), True, 0)
check('admin can change a role', as_user(ADMIN, "UPDATE user_profiles SET role='admin' WHERE id=%s", (USER,)), True, 1)
check('stranger sees no profiles', as_user(STRANGER, "SELECT * FROM user_profiles"), True, 0)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
