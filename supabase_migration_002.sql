-- =====================================================================
-- MBK Lounge — Шинэчлэл 002: постын "Батлагдсан" / "Татгалзсан" төлөв
-- Supabase SQL Editor дээр НЭГ удаа ажиллуулна. Дахин ажиллуулсан ч алдаагүй.
-- Өгөгдөл устгахгүй, зөвхөн зөвшөөрөгдөх төлөвийн жагсаалтыг өргөтгөнө.
-- =====================================================================

alter table public.content_drafts
  drop constraint if exists content_drafts_status_check;

alter table public.content_drafts
  add constraint content_drafts_status_check
  check (status in ('draft', 'review', 'approved', 'rejected',
                    'scheduled', 'published', 'archived'));
