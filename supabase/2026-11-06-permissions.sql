-- =============================================================
-- 業務報價 CRM：資料庫層權限修正（2026-11-06）
--
-- 修正前的問題：
--   1. 任何已登入帳號都能讀寫、刪除 app_data 的全部資料，
--      「業務員不能刪客戶／刪訂單／改設定」只在畫面上擋。
--   2. user_profiles 的更新規則沒限制欄位，業務員可以把自己的 role 改成 admin。
--   3. 只要有帳號就能讀資料；若 Supabase 開著「允許註冊」，陌生人註冊後就能看到全部客戶。
--
-- 修正後：
--   - 只有在 user_profiles 裡有資料的人才能讀寫 app_data
--   - 只有 admin 能改 settings（匯率、利潤表、產品範本）、能刪 app_data 的資料列
--   - 業務員存客戶（crm）、訂單（orders）時，不能讓既有的客戶／訂單消失
--   - 業務員從回收桶（trash）移除項目，只限「已還原」或「放超過 30 天」
--   - 只有 admin 能改任何人的 role
--
-- 執行方式：Supabase 後台 → SQL Editor → New query，
--   先跑【步驟 0】確認結果，再把【步驟 1】整段貼上執行。
--   整段包在交易裡，中途出錯會全部撤回。
-- =============================================================


-- -------------------------------------------------------------
-- 【步驟 0】執行前檢查（只讀不寫）
-- 列出所有帳號與角色。role 是空的人，修正後會無法登入使用，
-- 要先用檔案最下方的「補建帳號資料」幫他補上。
-- -------------------------------------------------------------
-- SELECT u.email, p.role, p.display_name
-- FROM auth.users u
-- LEFT JOIN public.user_profiles p ON p.id = u.id
-- ORDER BY p.role NULLS FIRST, u.email;


-- -------------------------------------------------------------
-- 【步驟 1】權限修正
-- -------------------------------------------------------------
BEGIN;

-- 判斷目前登入者身分（SECURITY DEFINER 才能在 RLS 內讀 user_profiles 而不遞迴）
CREATE OR REPLACE FUNCTION public.crm_is_admin()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_profiles WHERE id = auth.uid() AND role = 'admin');
$$;

CREATE OR REPLACE FUNCTION public.crm_is_member()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_profiles WHERE id = auth.uid());
$$;

-- 取出一個 JSON 陣列裡所有元素的 id（轉成文字比對，數字或字串 id 都能用）
CREATE OR REPLACE FUNCTION public.crm_ids(arr jsonb)
RETURNS SETOF text
LANGUAGE sql IMMUTABLE
AS $$
  SELECT e->>'id'
  FROM jsonb_array_elements(CASE WHEN jsonb_typeof(arr) = 'array' THEN arr ELSE '[]'::jsonb END) e
  WHERE e->>'id' IS NOT NULL;
$$;

-- ---------- app_data 的 RLS 規則 ----------
DROP POLICY IF EXISTS "auth_read_app_data"  ON public.app_data;
DROP POLICY IF EXISTS "auth_write_app_data" ON public.app_data;
DROP POLICY IF EXISTS "crm_select" ON public.app_data;
DROP POLICY IF EXISTS "crm_insert" ON public.app_data;
DROP POLICY IF EXISTS "crm_update" ON public.app_data;
DROP POLICY IF EXISTS "crm_delete" ON public.app_data;

CREATE POLICY "crm_select" ON public.app_data
  FOR SELECT TO authenticated USING (public.crm_is_member());

CREATE POLICY "crm_insert" ON public.app_data
  FOR INSERT TO authenticated
  WITH CHECK (public.crm_is_member() AND (key <> 'settings' OR public.crm_is_admin()));

CREATE POLICY "crm_update" ON public.app_data
  FOR UPDATE TO authenticated
  USING      (public.crm_is_member() AND (key <> 'settings' OR public.crm_is_admin()))
  WITH CHECK (public.crm_is_member() AND (key <> 'settings' OR public.crm_is_admin()));

CREATE POLICY "crm_delete" ON public.app_data
  FOR DELETE TO authenticated USING (public.crm_is_admin());

-- ---------- 業務員不能讓客戶／訂單消失 ----------
-- app_data 是「一個 key 存一整個陣列」，RLS 看不到陣列內容，
-- 所以用 trigger 比對更新前後的陣列內容。
CREATE OR REPLACE FUNCTION public.crm_guard_app_data()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  missing  text;
  cur_live jsonb;
BEGIN
  -- 管理者、或後台 SQL Editor／service role（沒有登入者）不受限
  IF auth.uid() IS NULL OR public.crm_is_admin() THEN
    RETURN NEW;
  END IF;

  IF NEW.key IN ('crm', 'orders') THEN
    SELECT o INTO missing
    FROM public.crm_ids(OLD.value) o
    WHERE o NOT IN (SELECT public.crm_ids(NEW.value))
    LIMIT 1;
    IF missing IS NOT NULL THEN
      RAISE EXCEPTION 'CRM_PERMISSION: 只有管理者可以刪除%（id %）',
        CASE NEW.key WHEN 'crm' THEN '客戶' ELSE '訂單' END, missing
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.key = 'trash' THEN
    -- 每個被移出回收桶的項目，必須是「已還原回清單」或「刪除超過 29 天（容許時區誤差）」
    FOR missing, cur_live IN
      SELECT x.e->>'id',
             (SELECT value FROM public.app_data
               WHERE key = CASE x.kind WHEN 'customers' THEN 'crm' ELSE 'orders' END)
      FROM (
        SELECT 'customers' AS kind, e FROM jsonb_array_elements(COALESCE(OLD.value->'customers', '[]')) e
        UNION ALL
        SELECT 'orders', e FROM jsonb_array_elements(COALESCE(OLD.value->'orders', '[]')) e
      ) x
      WHERE x.e->>'id' NOT IN (
              SELECT public.crm_ids(NEW.value->x.kind))
        AND COALESCE(x.e->>'deletedAt', '') >= to_char((now() AT TIME ZONE 'utc')::date - 29, 'YYYY-MM-DD')
    LOOP
      IF missing NOT IN (SELECT public.crm_ids(cur_live)) THEN
        RAISE EXCEPTION 'CRM_PERMISSION: 只有管理者可以永久刪除回收桶項目（id %）', missing
          USING ERRCODE = '42501';
      END IF;
    END LOOP;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS crm_guard_app_data ON public.app_data;
CREATE TRIGGER crm_guard_app_data
  BEFORE UPDATE ON public.app_data
  FOR EACH ROW EXECUTE FUNCTION public.crm_guard_app_data();

-- ---------- user_profiles：不能自己升級成 admin ----------
DROP POLICY IF EXISTS "auth_read_profiles"      ON public.user_profiles;
DROP POLICY IF EXISTS "auth_update_own_profile" ON public.user_profiles;
DROP POLICY IF EXISTS "crm_profiles_select"     ON public.user_profiles;
DROP POLICY IF EXISTS "crm_profiles_update"     ON public.user_profiles;

CREATE POLICY "crm_profiles_select" ON public.user_profiles
  FOR SELECT TO authenticated USING (public.crm_is_member());

CREATE POLICY "crm_profiles_update" ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (auth.uid() = id OR public.crm_is_admin())
  WITH CHECK (auth.uid() = id OR public.crm_is_admin());

CREATE OR REPLACE FUNCTION public.crm_guard_role()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NOT NULL AND NEW.role IS DISTINCT FROM OLD.role AND NOT public.crm_is_admin() THEN
    RAISE EXCEPTION 'CRM_PERMISSION: 只有管理者可以變更角色' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS crm_guard_role ON public.user_profiles;
CREATE TRIGGER crm_guard_role
  BEFORE UPDATE ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.crm_guard_role();

COMMIT;


-- -------------------------------------------------------------
-- 補建帳號資料（步驟 0 有人 role 是空的才需要；把 email、姓名換掉）
-- -------------------------------------------------------------
-- INSERT INTO public.user_profiles (id, role, display_name)
-- SELECT id, 'user', '業務員姓名' FROM auth.users WHERE email = 'someone@example.com'
-- ON CONFLICT (id) DO NOTHING;


-- -------------------------------------------------------------
-- 還原（萬一要撤回這次修正，回到原本「登入就能全部讀寫」的狀態）
-- -------------------------------------------------------------
-- BEGIN;
-- DROP TRIGGER IF EXISTS crm_guard_app_data ON public.app_data;
-- DROP TRIGGER IF EXISTS crm_guard_role ON public.user_profiles;
-- DROP POLICY IF EXISTS "crm_select" ON public.app_data;
-- DROP POLICY IF EXISTS "crm_insert" ON public.app_data;
-- DROP POLICY IF EXISTS "crm_update" ON public.app_data;
-- DROP POLICY IF EXISTS "crm_delete" ON public.app_data;
-- DROP POLICY IF EXISTS "crm_profiles_select" ON public.user_profiles;
-- DROP POLICY IF EXISTS "crm_profiles_update" ON public.user_profiles;
-- CREATE POLICY "auth_read_app_data"  ON public.app_data FOR SELECT TO authenticated USING (true);
-- CREATE POLICY "auth_write_app_data" ON public.app_data FOR ALL    TO authenticated USING (true);
-- CREATE POLICY "auth_read_profiles"  ON public.user_profiles FOR SELECT TO authenticated USING (true);
-- CREATE POLICY "auth_update_own_profile" ON public.user_profiles FOR UPDATE TO authenticated USING (auth.uid() = id);
-- COMMIT;
