-- Цикл на двоих: схема и правила доступа.
-- Выполнить один раз: Supabase → SQL Editor → New query → вставить весь текст → Run.

-- Все документы приложения. path = путь документа, owner = кто его создал.
create table if not exists public.docs (
  path text primary key,
  owner uuid not null references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- Одноразовые коды приглашения партнёра.
create table if not exists public.invites (
  code text primary key,
  owner uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Пары: a = владелица цикла, b = партнёр.
create table if not exists public.pairs (
  a uuid not null references auth.users(id) on delete cascade,
  b uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (a, b),
  check (a <> b)
);

create or replace function public.is_paired(x uuid, y uuid)
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.pairs where (a = x and b = y) or (a = y and b = x));
$$;

alter table public.docs enable row level security;
alter table public.invites enable row level security;
alter table public.pairs enable row level security;

-- 1. Владелец полностью управляет своими документами (приватная зона data/users/... тоже здесь).
drop policy if exists docs_owner_all on public.docs;
create policy docs_owner_all on public.docs for all to authenticated
  using (owner = auth.uid())
  with check (owner = auth.uid());

-- 2. Партнёр читает только общую копию владелицы: shared/<её id>.
drop policy if exists docs_partner_read_shared on public.docs;
create policy docs_partner_read_shared on public.docs for select to authenticated
  using (path = 'shared/' || owner::text and public.is_paired(owner, auth.uid()));

-- 3. Аллергены общие для пары: оба могут добавлять, править и удалять.
drop policy if exists docs_pair_allergens on public.docs;
create policy docs_pair_allergens on public.docs for all to authenticated
  using (path like 'allergens/%' and public.is_paired(owner, auth.uid()))
  with check (path like 'allergens/%' and (owner = auth.uid() or public.is_paired(owner, auth.uid())));

-- Приглашения: владелец создаёт и видит только свои.
drop policy if exists invites_owner on public.invites;
create policy invites_owner on public.invites for all to authenticated
  using (owner = auth.uid())
  with check (owner = auth.uid());

-- Пары: видим и можем разорвать только свои. Создаются только через функцию accept_invite.
drop policy if exists pairs_members_read on public.pairs;
create policy pairs_members_read on public.pairs for select to authenticated
  using (a = auth.uid() or b = auth.uid());

drop policy if exists pairs_members_delete on public.pairs;
create policy pairs_members_delete on public.pairs for delete to authenticated
  using (a = auth.uid() or b = auth.uid());

-- Партнёр принимает код: создаётся пара и код сгорает.
create or replace function public.accept_invite(p_code text)
returns void
language plpgsql security definer set search_path = public
as $$
declare
  inv_owner uuid;
  code_clean text := upper(trim(p_code));
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  select owner into inv_owner from public.invites where code = code_clean;
  if inv_owner is null then raise exception 'invite_not_found'; end if;
  if inv_owner = auth.uid() then raise exception 'own_invite'; end if;
  insert into public.pairs (a, b) values (inv_owner, auth.uid()) on conflict do nothing;
  delete from public.invites where code = code_clean;
end;
$$;

revoke all on function public.accept_invite(text) from public;
grant execute on function public.accept_invite(text) to authenticated;

-- Живые обновления для второго телефона (с учётом тех же правил доступа).
alter publication supabase_realtime add table public.docs;
