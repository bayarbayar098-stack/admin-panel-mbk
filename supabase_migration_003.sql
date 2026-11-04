-- =====================================================================
-- MBK Lounge — Шинэчлэл 003: reservations (ширээ захиалга) + staff (ажилтан)
--
-- Supabase SQL Editor дээр бүтнээр нь хуулж Run дарна.
-- Дахин ажиллуулсан ч алдаа гарахгүй, жишээ мөр давхардахгүй.
-- Postgres функц, trigger шинээр бичээгүй.
-- Цалин, регистрийн дугаар зэрэг нууц мэдээллийн талбар байхгүй.
--
-- staff хүснэгт өмнө нь (supabase.sql) үүссэн тул УСТГАХГҮЙ — шаардлагатай
-- баганыг нэмж, хуучин утгыг шинэ хэлбэрт хөрвүүлнэ. Өгөгдөл алдагдахгүй.
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 1. reservations — ширээ захиалга
-- ---------------------------------------------------------------------
create table if not exists public.reservations (
  id                uuid primary key default gen_random_uuid(),
  guest_name        text not null check (char_length(guest_name) between 1 and 120),
  phone             text not null check (phone ~ '^[0-9+ -]{6,20}$'),
  reservation_date  date not null,
  start_time        time not null,
  guest_count       integer not null check (guest_count between 1 and 200),
  seating           text not null default 'table'
                    check (seating in ('table', 'vip_room')),       -- ширээ / VIP өрөө
  seat_label        text check (seat_label is null or char_length(seat_label) <= 40),
                    -- жишээ: 'Ширээ 4', 'VIP 2' (заавал биш)
  status            text not null default 'pending'
                    check (status in ('pending', 'confirmed', 'cancelled', 'completed')),
                    -- хүлээгдэж буй / баталгаажсан / цуцалсан / дууссан
  deposit_amount    numeric(12, 2) not null default 0 check (deposit_amount >= 0),
                    -- урьдчилгаа (төгрөг)
  notes             text check (notes is null or char_length(notes) <= 1000),
  created_at        timestamptz not null default now()
);

create index if not exists reservations_date_idx   on public.reservations (reservation_date);
create index if not exists reservations_status_idx on public.reservations (status);

-- ---------------------------------------------------------------------
-- 2. staff — ажилтан (байгаа хүснэгтийг өргөтгөнө)
-- ---------------------------------------------------------------------
-- Хэрэв өмнө нь огт үүсээгүй бол үндсэн хэлбэрээр үүсгэнэ
create table if not exists public.staff (
  id          uuid primary key default gen_random_uuid(),
  full_name   text not null check (char_length(full_name) between 1 and 120),
  position    text not null,
  phone       text,
  email       text,
  is_active   boolean not null default true,
  created_at  timestamptz not null default now()
);

alter table public.staff add column if not exists shift    text;  -- day / night
alter table public.staff add column if not exists status   text;  -- active / on_leave / left
alter table public.staff add column if not exists hired_at date;  -- ажилд орсон огноо

-- Хуучин мөрүүдийг шинэ хэлбэрт хөрвүүлэх (зөвхөн хоосон утгыг бөглөнө —
-- дахин ажиллуулахад самбараас хийсэн өөрчлөлтийг дарж бичихгүй)
update public.staff set shift = 'day' where shift is null;
update public.staff
   set status = case when is_active then 'active' else 'left' end
 where status is null;
update public.staff
   set position = case position
                    when 'Менежер'    then 'manager'
                    when 'Бармен'     then 'bartender'
                    when 'Зөөгч'      then 'waiter'
                    when 'Кассчин'    then 'cashier'
                    when 'Хамгаалагч' then 'security'
                    else position
                  end
 where position in ('Менежер', 'Бармен', 'Зөөгч', 'Кассчин', 'Хамгаалагч');

alter table public.staff alter column shift  set default 'day';
alter table public.staff alter column shift  set not null;
alter table public.staff alter column status set default 'active';
alter table public.staff alter column status set not null;

alter table public.staff drop constraint if exists staff_shift_check;
alter table public.staff add  constraint staff_shift_check
  check (shift in ('day', 'night'));                                   -- өдөр / орой

alter table public.staff drop constraint if exists staff_status_check;
alter table public.staff add  constraint staff_status_check
  check (status in ('active', 'on_leave', 'left'));                    -- идэвхтэй / чөлөөтэй / гарсан

-- Шинэ болон засварласан мөрөнд л шалгана (хуучин өөр утга байвал алдаа өгөхгүй)
alter table public.staff drop constraint if exists staff_position_check;
alter table public.staff add  constraint staff_position_check
  check (position in ('manager', 'bartender', 'waiter', 'cashier', 'security')) not valid;

alter table public.staff drop constraint if exists staff_phone_check;
alter table public.staff add  constraint staff_phone_check
  check (phone is null or phone ~ '^[0-9+ -]{6,20}$') not valid;

create index if not exists staff_status_idx on public.staff (status);

-- ---------------------------------------------------------------------
-- 3. Эрх: нэвтрээгүй (anon) хэрэглэгч огт хандахгүй
-- ---------------------------------------------------------------------
revoke all on public.reservations, public.staff from anon;
grant select, insert, update, delete on public.reservations, public.staff to authenticated;

-- ---------------------------------------------------------------------
-- 4. RLS + policy
--    Зөвхөн нэвтэрсэн (authenticated) хэрэглэгч, ДЭЭР НЬ admins жагсаалтад
--    байгаа хүн. (Төсөлд өөрөө бүртгүүлэх боломж нээлттэй тул зөвхөн
--    "нэвтэрсэн" гэсэн шалгалт хангалтгүй — хэн ч бүртгүүлээд орж болно.)
--    Шинэ функц бичихгүйн тулд admins хүснэгтийг шууд шалгана.
-- ---------------------------------------------------------------------
alter table public.reservations enable row level security;
alter table public.staff        enable row level security;

-- reservations
drop policy if exists "reservations_select" on public.reservations;
drop policy if exists "reservations_insert" on public.reservations;
drop policy if exists "reservations_update" on public.reservations;
drop policy if exists "reservations_delete" on public.reservations;
create policy "reservations_select" on public.reservations for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "reservations_insert" on public.reservations for insert to authenticated
  with check (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "reservations_update" on public.reservations for update to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())))
  with check (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "reservations_delete" on public.reservations for delete to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));

-- staff (өмнөх admin_* бодлогыг ижил утгатай шинэ бодлогоор солино)
drop policy if exists "admin_select" on public.staff;
drop policy if exists "admin_insert" on public.staff;
drop policy if exists "admin_update" on public.staff;
drop policy if exists "admin_delete" on public.staff;
drop policy if exists "staff_select" on public.staff;
drop policy if exists "staff_insert" on public.staff;
drop policy if exists "staff_update" on public.staff;
drop policy if exists "staff_delete" on public.staff;
create policy "staff_select" on public.staff for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "staff_insert" on public.staff for insert to authenticated
  with check (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "staff_update" on public.staff for update to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())))
  with check (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));
create policy "staff_delete" on public.staff for delete to authenticated
  using (exists (select 1 from public.admins a where a.user_id = (select auth.uid())));

-- ---------------------------------------------------------------------
-- 5. Зохиомол жишээ мөр (9900xxxx хуурамч утас)
--    Утсаар нь шалгаж, аль хэдийн байгаа бол дахин нэмэхгүй.
-- ---------------------------------------------------------------------
insert into public.reservations
  (guest_name, phone, reservation_date, start_time, guest_count, seating, seat_label,
   status, deposit_amount, notes)
select v.* from (values
  ('Туршилт Бат-Эрдэнэ', '99001001', date '2026-11-07', time '19:00', 4,  'table',    'Ширээ 4',
   'confirmed', 0::numeric,      'Цонхны дэргэд'),
  ('Жишээ Номин',        '99001002', date '2026-11-14', time '20:30', 8,  'vip_room', 'VIP 1',
   'pending',   100000::numeric, 'Төрсөн өдөр, бялуу авчирна'),
  ('Зохиомол Тэмүүжин',  '99001003', date '2026-11-02', time '18:00', 2,  'table',    null,
   'completed', 0::numeric,      null)
) as v(guest_name, phone, reservation_date, start_time, guest_count, seating, seat_label,
       status, deposit_amount, notes)
where not exists (select 1 from public.reservations r where r.phone = v.phone);

insert into public.staff (full_name, position, phone, shift, status, hired_at)
select v.* from (values
  ('Туршилт Саруул',   'bartender', '99002001', 'night', 'active',   date '2025-03-01'),
  ('Жишээ Энхжин',     'cashier',   '99002002', 'day',   'on_leave', date '2024-09-15'),
  ('Зохиомол Ганбаатар','security', '99002003', 'night', 'left',     date '2023-06-10')
) as v(full_name, position, phone, shift, status, hired_at)
where not exists (select 1 from public.staff s where s.phone = v.phone);

commit;
