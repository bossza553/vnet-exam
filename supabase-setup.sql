-- ============================================================
-- V-NET ติวเตอร์ — ระบบบัญชีผู้ใช้ + CD-Key
-- วิธีใช้: Supabase Dashboard -> SQL Editor -> New query
--          วางทั้งไฟล์นี้ แล้วกด RUN (ครั้งเดียวจบ)
-- ============================================================

-- โปรไฟล์ผู้ใช้ (สร้างอัตโนมัติเมื่อสมัครสมาชิก)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  licensed boolean not null default false,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

-- คลังรหัส CD-Key
create table if not exists public.license_keys (
  key text primary key,
  batch text not null default 'default',
  created_at timestamptz not null default now(),
  activated_by uuid references auth.users(id) on delete set null,
  activated_email text,
  activated_at timestamptz,
  revoked boolean not null default false
);

alter table public.profiles enable row level security;
alter table public.license_keys enable row level security;

-- เช็คสิทธิ์แอดมิน (security definer เพื่อเลี่ยง RLS recursion)
create or replace function public.check_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- สร้างโปรไฟล์อัตโนมัติเมื่อมีผู้สมัคร / bossza9000@gmail.com = super admin
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, is_admin)
  values (new.id, lower(new.email), lower(new.email) = 'bossza9000@gmail.com')
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- นโยบายการเข้าถึง
drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles
  for select using (auth.uid() = id or public.check_admin());

drop policy if exists "admin read keys" on public.license_keys;
create policy "admin read keys" on public.license_keys
  for select using (public.check_admin());

-- เปิดใช้งานรหัส (ผูกรหัสกับบัญชี)
create or replace function public.activate_key(k text) returns text
language plpgsql security definer set search_path = public as $$
declare
  norm text := upper(regexp_replace(k, '[^A-Za-z0-9]', '', 'g'));
  formatted text;
  rec public.license_keys;
begin
  if auth.uid() is null then return 'not-signed-in'; end if;
  if length(norm) <> 16 then return 'invalid'; end if;
  formatted := substr(norm,1,4)||'-'||substr(norm,5,4)||'-'||substr(norm,9,4)||'-'||substr(norm,13,4);
  select * into rec from public.license_keys where key = formatted;
  if not found then return 'invalid'; end if;
  if rec.revoked then return 'revoked'; end if;
  if rec.activated_by is not null and rec.activated_by <> auth.uid() then return 'used'; end if;
  update public.license_keys
     set activated_by = auth.uid(),
         activated_email = (select email from public.profiles where id = auth.uid()),
         activated_at = coalesce(activated_at, now())
   where key = formatted;
  update public.profiles set licensed = true where id = auth.uid();
  return 'ok';
end $$;

-- สถานะของฉัน (client เรียกทุกครั้งที่เปิดแอป)
create or replace function public.my_status() returns json
language sql security definer stable set search_path = public as $$
  select json_build_object(
    'licensed', coalesce((select licensed from public.profiles where id = auth.uid()), false),
    'is_admin', coalesce((select is_admin from public.profiles where id = auth.uid()), false),
    'email',    (select email from public.profiles where id = auth.uid())
  )
$$;

-- แอดมิน: สร้างรหัสเป็นชุด (สูงสุด 1000 ต่อครั้ง)
create or replace function public.admin_generate_keys(n int, batch_name text default 'default')
returns setof text language plpgsql security definer set search_path = public as $$
declare
  alph text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  body text; k text; i int := 0; tries int := 0;
begin
  if not public.check_admin() then raise exception 'not admin'; end if;
  if n < 1 or n > 1000 then raise exception 'n out of range (1-1000)'; end if;
  while i < n and tries < n * 3 loop
    tries := tries + 1;
    body := '';
    for j in 1..16 loop
      body := body || substr(alph, 1 + floor(random()*32)::int, 1);
    end loop;
    k := substr(body,1,4)||'-'||substr(body,5,4)||'-'||substr(body,9,4)||'-'||substr(body,13,4);
    begin
      insert into public.license_keys(key, batch) values (k, coalesce(nullif(trim(batch_name),''),'default'));
      i := i + 1;
      return next k;
    exception when unique_violation then null;
    end;
  end loop;
end $$;

-- แอดมิน: ระงับ/คืนสิทธิ์รหัส (ผู้ใช้ที่ถือรหัสจะถูกล็อกทันที)
create or replace function public.admin_revoke_key(k text, unrevoke boolean default false)
returns text language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  if not public.check_admin() then raise exception 'not admin'; end if;
  update public.license_keys set revoked = (not unrevoke) where key = k
    returning activated_by into uid;
  if not found then return 'not-found'; end if;
  if uid is not null then
    update public.profiles set licensed = exists(
      select 1 from public.license_keys lk
       where lk.activated_by = uid and lk.activated_at is not null and not lk.revoked
    ) where id = uid;
  end if;
  return 'ok';
end $$;

-- นำเข้ารหัสชุดแรก 10 รหัสที่แจกไปแล้ว (ยังใช้ได้ต่อเนื่อง)
insert into public.license_keys (key, batch) values
  ('L35L-A4SK-73RQ-694G','ชุดแรก'),
  ('U25L-KAR4-92FB-ZHZA','ชุดแรก'),
  ('6KQZ-N2CU-KMNB-296M','ชุดแรก'),
  ('KNEF-463K-YASD-VJGQ','ชุดแรก'),
  ('V69M-RHFR-U8EF-L4AY','ชุดแรก'),
  ('GTYD-K4R4-Z3AX-3L5N','ชุดแรก'),
  ('MNXM-ZUYD-RNPC-FC76','ชุดแรก'),
  ('4LHV-CQDG-ANBP-YT5P','ชุดแรก'),
  ('W8BU-CWEH-AJGN-HSPB','ชุดแรก'),
  ('CF9Z-2X82-YP3M-HX2F','ชุดแรก')
on conflict (key) do nothing;
