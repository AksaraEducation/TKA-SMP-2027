-- AksaraEdu: profil akun dan keamanan dasar Supabase
-- Jalankan sekali melalui Supabase Dashboard > SQL Editor.
-- Role tidak diambil dari metadata pendaftaran pengguna agar pengguna tidak dapat menaikkan hak akses sendiri.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'student' check (role in ('admin','teacher','student')),
  school_id uuid null,
  class_id uuid null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Fungsi SECURITY DEFINER menghindari policy membaca tabel profiles melalui RLS yang sama.
create or replace function public.is_aksara_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$;

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles
for select to authenticated using (id = auth.uid());

drop policy if exists "Admins can read all profiles" on public.profiles;
create policy "Admins can read all profiles" on public.profiles
for select to authenticated using (
  public.is_aksara_admin()
);

drop policy if exists "Admins can insert profiles" on public.profiles;
create policy "Admins can insert profiles" on public.profiles
for insert to authenticated with check (
  public.is_aksara_admin()
);

drop policy if exists "Admins can update profiles" on public.profiles;
create policy "Admins can update profiles" on public.profiles
for update to authenticated using (
  public.is_aksara_admin()
) with check (
  public.is_aksara_admin()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    'student'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Penting: setelah akun pertama dibuat, administrator harus mengubah role akun tersebut
-- menjadi 'admin' secara manual melalui SQL Editor. Jangan membuka hak admin untuk pendaftaran publik.
