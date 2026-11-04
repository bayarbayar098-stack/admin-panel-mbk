-- =====================================================================
-- MBK Lounge — Админ самбарын өгөгдлийн сан (Хувилбар 1)
-- Supabase SQL Editor дээр бүтнээр нь нэг удаа ажиллуулна.
-- Дахин ажиллуулахад алдаа гаргахгүй (re-runnable), жишээ мөрийг давхардуулахгүй.
--
-- Нууц үгийг энд ХАДГАЛАХГҮЙ. Нэвтрэлтийг Supabase Auth (auth.users) хариуцна.
-- Хэн админ болохыг public.admins хүснэгтэд auth.users-ийн id-гаар тэмдэглэнэ.
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 0. Админуудын жагсаалт (зөвхөн Auth хэрэглэгчийн id хадгална)
-- ---------------------------------------------------------------------
create table if not exists public.admins (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Нэвтэрсэн хэрэглэгч админ эсэхийг шалгах функц.
-- security definer тул admins хүснэгтийн RLS-д гацахгүй.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admins a where a.user_id = auth.uid()
  );
$$;

revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- updated_at талбарыг автоматаар шинэчлэх trigger функц
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------
-- 1. content_drafts — Сошиал/вэб постын ноорог
-- ---------------------------------------------------------------------
create table if not exists public.content_drafts (
  id          uuid primary key default gen_random_uuid(),
  title       text not null check (char_length(title) between 1 and 200),
  body        text not null,
  channel     text not null
              check (channel in ('facebook', 'instagram', 'tiktok', 'website', 'email')),
  status      text not null default 'draft'
              check (status in ('draft', 'review', 'approved', 'rejected',
                                'scheduled', 'published', 'archived')),
  publish_at  timestamptz,
  created_by  uuid references auth.users (id) on delete set null default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  -- "scheduled" төлөвтэй бол нийтлэх огноо заавал байх ёстой
  constraint content_drafts_scheduled_needs_date
    check (status <> 'scheduled' or publish_at is not null)
);

create index if not exists content_drafts_status_idx     on public.content_drafts (status);
create index if not exists content_drafts_publish_at_idx on public.content_drafts (publish_at);

-- ---------------------------------------------------------------------
-- 2. bookings — Ширээ / VIP өрөөний захиалга
-- ---------------------------------------------------------------------
create table if not exists public.bookings (
  id             uuid primary key default gen_random_uuid(),
  customer_name  text not null check (char_length(customer_name) between 1 and 120),
  phone          text,
  email          text check (email is null or email like '%_@_%.__%'),
  booking_date   date not null,
  booking_time   time,
  guest_count    integer not null check (guest_count between 1 and 500),
  booking_type   text not null default 'table'
                 check (booking_type in ('table', 'vip_room', 'birthday', 'corporate', 'other')),
  vip_room       text,           -- жишээ: 'VIP 1', 'VIP 2'. VIP биш бол хоосон
  status         text not null default 'pending'
                 check (status in ('pending', 'confirmed', 'seated', 'completed', 'cancelled', 'no_show')),
  notes          text,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  -- Утас эсвэл имэйлийн аль нэг нь заавал байх
  constraint bookings_contact_required check (phone is not null or email is not null),
  -- VIP өрөөний захиалга бол өрөөний нэр заавал байх
  constraint bookings_vip_room_required check (booking_type <> 'vip_room' or vip_room is not null)
);

create index if not exists bookings_date_idx   on public.bookings (booking_date);
create index if not exists bookings_status_idx on public.bookings (status);

-- ---------------------------------------------------------------------
-- 3. events — Арга хэмжээ
-- ---------------------------------------------------------------------
create table if not exists public.events (
  id           uuid primary key default gen_random_uuid(),
  name         text not null check (char_length(name) between 1 and 200),
  event_date   date not null,
  start_time   time,
  guest_count  integer check (guest_count is null or guest_count between 1 and 2000),
  status       text not null default 'planned'
               check (status in ('planned', 'confirmed', 'in_progress', 'completed', 'cancelled')),
  notes        text,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create index if not exists events_date_idx   on public.events (event_date);
create index if not exists events_status_idx on public.events (status);

-- ---------------------------------------------------------------------
-- 4. staff — Ажилтнууд (нууц үг хадгалахгүй)
-- ---------------------------------------------------------------------
create table if not exists public.staff (
  id          uuid primary key default gen_random_uuid(),
  full_name   text not null check (char_length(full_name) between 1 and 120),
  position    text not null,
  phone       text,
  email       text check (email is null or email like '%_@_%.__%'),
  is_active   boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists staff_is_active_idx on public.staff (is_active);

-- ---------------------------------------------------------------------
-- 5. updated_at trigger-үүд
-- ---------------------------------------------------------------------
drop trigger if exists set_updated_at on public.content_drafts;
create trigger set_updated_at before update on public.content_drafts
  for each row execute function public.set_updated_at();

drop trigger if exists set_updated_at on public.bookings;
create trigger set_updated_at before update on public.bookings
  for each row execute function public.set_updated_at();

drop trigger if exists set_updated_at on public.events;
create trigger set_updated_at before update on public.events
  for each row execute function public.set_updated_at();

drop trigger if exists set_updated_at on public.staff;
create trigger set_updated_at before update on public.staff
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------
-- 6. Эрх: нэвтрээгүй (anon) хэрэглэгчид огт хандахгүй
-- ---------------------------------------------------------------------
revoke all on public.admins, public.content_drafts, public.bookings,
              public.events, public.staff from anon;

grant select on public.admins to authenticated;
grant select, insert, update, delete
  on public.content_drafts, public.bookings, public.events, public.staff
  to authenticated;

-- ---------------------------------------------------------------------
-- 7. RLS асаах
-- ---------------------------------------------------------------------
alter table public.admins          enable row level security;
alter table public.content_drafts  enable row level security;
alter table public.bookings        enable row level security;
alter table public.events          enable row level security;
alter table public.staff           enable row level security;

-- ---------------------------------------------------------------------
-- 8. RLS бодлогууд — зөвхөн нэвтэрсэн АДМИН
-- ---------------------------------------------------------------------

-- admins: хэрэглэгч зөвхөн өөрийн мөрийг харна (админ эсэхээ шалгахад).
-- Админ нэмэх/хасахыг зөвхөн SQL Editor-оор хийнэ (апп-аас боломжгүй).
drop policy if exists "admins_select_self" on public.admins;
create policy "admins_select_self" on public.admins
  for select to authenticated
  using (user_id = (select auth.uid()));

-- content_drafts
drop policy if exists "admin_select" on public.content_drafts;
drop policy if exists "admin_insert" on public.content_drafts;
drop policy if exists "admin_update" on public.content_drafts;
drop policy if exists "admin_delete" on public.content_drafts;
create policy "admin_select" on public.content_drafts for select to authenticated
  using ((select public.is_admin()));
create policy "admin_insert" on public.content_drafts for insert to authenticated
  with check ((select public.is_admin()));
create policy "admin_update" on public.content_drafts for update to authenticated
  using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "admin_delete" on public.content_drafts for delete to authenticated
  using ((select public.is_admin()));

-- bookings
drop policy if exists "admin_select" on public.bookings;
drop policy if exists "admin_insert" on public.bookings;
drop policy if exists "admin_update" on public.bookings;
drop policy if exists "admin_delete" on public.bookings;
create policy "admin_select" on public.bookings for select to authenticated
  using ((select public.is_admin()));
create policy "admin_insert" on public.bookings for insert to authenticated
  with check ((select public.is_admin()));
create policy "admin_update" on public.bookings for update to authenticated
  using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "admin_delete" on public.bookings for delete to authenticated
  using ((select public.is_admin()));

-- events
drop policy if exists "admin_select" on public.events;
drop policy if exists "admin_insert" on public.events;
drop policy if exists "admin_update" on public.events;
drop policy if exists "admin_delete" on public.events;
create policy "admin_select" on public.events for select to authenticated
  using ((select public.is_admin()));
create policy "admin_insert" on public.events for insert to authenticated
  with check ((select public.is_admin()));
create policy "admin_update" on public.events for update to authenticated
  using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "admin_delete" on public.events for delete to authenticated
  using ((select public.is_admin()));

-- staff
drop policy if exists "admin_select" on public.staff;
drop policy if exists "admin_insert" on public.staff;
drop policy if exists "admin_update" on public.staff;
drop policy if exists "admin_delete" on public.staff;
create policy "admin_select" on public.staff for select to authenticated
  using ((select public.is_admin()));
create policy "admin_insert" on public.staff for insert to authenticated
  with check ((select public.is_admin()));
create policy "admin_update" on public.staff for update to authenticated
  using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "admin_delete" on public.staff for delete to authenticated
  using ((select public.is_admin()));

-- ---------------------------------------------------------------------
-- 9. Зохиомол жишээ өгөгдөл (хүснэгт хоосон үед л нэмнэ)
--    Утас: +976 0000 xxxx (бодит дугаар биш)
--    Имэйл: @example.com (RFC 2606-оор туршилтад зориулсан домэйн)
-- ---------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from public.content_drafts) then
    insert into public.content_drafts (title, body, channel, status, publish_at, created_by) values
      ('Баасан гарагийн DJ үдэш',
       'Энэ баасан гарагт MBK Lounge-д DJ сет болно. Ширээгээ урьдчилан захиалаарай!',
       'instagram', 'scheduled', '2026-11-13 18:00:00+08', null),
      ('Шинэ коктейлийн цэс',
       'Өвлийн улиралд зориулсан 5 шинэ коктейль цэсэнд нэмэгдлээ.',
       'facebook', 'review', null, null),
      ('VIP өрөөний танилцуулга',
       'Хувийн уулзалт, төрсөн өдөрт тохиромжтой VIP өрөөнүүдийн тухай.',
       'website', 'draft', null, null);
  end if;

  if not exists (select 1 from public.bookings) then
    insert into public.bookings
      (customer_name, phone, email, booking_date, booking_time, guest_count, booking_type, vip_room, status, notes) values
      ('Туршилт Болд',   '+976 0000 0001', null,                    '2026-11-07', '19:30', 4,  'table',     null,    'confirmed', 'Цонхны дэргэд суух хүсэлттэй'),
      ('Жишээ Сараа',    null,             'saraa.demo@example.com', '2026-11-14', '20:00', 10, 'vip_room',  'VIP 1', 'pending',   'Төрсөн өдрийн бялуу авчирна'),
      ('Зохиомол Компани ХХК', '+976 0000 0002', 'booking@example.com', '2026-11-21', '18:00', 25, 'corporate', null, 'pending', 'Жилийн эцсийн уулзалт, проектор хэрэгтэй');
  end if;

  if not exists (select 1 from public.events) then
    insert into public.events (name, event_date, start_time, guest_count, status, notes) values
      ('Live Jazz Night',          '2026-11-20', '20:00', 80,  'confirmed', 'Хамтлагийн дууны шалгалт 17:00-д'),
      ('Шинэ жилийн үдэшлэг',      '2026-12-31', '21:00', 200, 'planned',   'Тасалбарын үнэ батлагдаагүй'),
      ('Хаалттай дегустаци',       '2026-11-11', '19:00', 20,  'completed', 'Урилгаар оролцсон');
  end if;

  if not exists (select 1 from public.staff) then
    insert into public.staff (full_name, position, phone, email, is_active) values
      ('Туршилт Ганаа',   'Менежер',  '+976 0000 0101', 'manager.demo@example.com', true),
      ('Жишээ Тэмүүлэн',  'Бармен',   '+976 0000 0102', null,                        true),
      ('Зохиомол Номин',  'Зөөгч',    null,             'waiter.demo@example.com',  false);
  end if;
end;
$$;

commit;

-- =====================================================================
-- 10. АДМИН НЭМЭХ (дээрх скрипт амжилттай болсны ДАРАА тусад нь ажиллуулна)
--     1) Authentication → Users → "Add user" хийж админ хэрэглэгч үүсгэнэ.
--     2) Доорх мөрийн имэйлийг тэр хэрэглэгчийн имэйлээр сольж, тайлбар (--)-ыг
--        устгаад ажиллуулна:
--
-- insert into public.admins (user_id)
-- select id from auth.users where email = 'admin-email-ээ-энд-бич'
-- on conflict (user_id) do nothing;
--
--     Шалгах:  select * from public.admins;
-- =====================================================================
