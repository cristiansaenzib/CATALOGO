-- IZAN CATALOGO MULTIPUNTO - INSTALACION EN UN SOLO SQL
-- Antes de ejecutar: crea UN usuario administrador en Supabase > Authentication > Users.
-- Ejecuta este archivo completo en SQL Editor. Ese usuario quedara como administrador.
-- Los puntos se crean desde la web y reciben un PIN propio.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.admins(user_id uuid primary key references auth.users(id) on delete cascade);
create table if not exists public.puntos(
  nombre text primary key,
  slug text unique,
  direccion text not null default '',
  creado timestamptz not null default now()
);
alter table public.puntos add column if not exists slug text;
alter table public.puntos add column if not exists direccion text not null default '';
update public.puntos set slug=trim(both '-' from regexp_replace(translate(lower(nombre),'áéíóúüñ','aeiouun'),'[^a-z0-9]+','-','g')) where slug is null;
create unique index if not exists puntos_slug_uidx on public.puntos(slug);

create table if not exists public.perfiles(
  user_id uuid primary key references auth.users(id) on delete cascade,
  punto text not null references public.puntos(nombre) on update cascade on delete cascade
);
create table if not exists public.refs(
  id uuid primary key default gen_random_uuid(),
  parent_id uuid references public.refs(id) on delete cascade,
  punto text not null references public.puntos(nombre) on update cascade on delete cascade,
  name text not null, theme text default 'marfil', pos int default 0,
  price_detal text, price_dist text, price_mayor text
);
create table if not exists public.photos(
  id uuid primary key default gen_random_uuid(),
  ref_id uuid references public.refs(id) on delete cascade,
  punto text not null references public.puntos(nombre) on update cascade on delete cascade,
  path text not null, pos int default 0
);
create index if not exists refs_punto_idx on public.refs(punto);
create index if not exists photos_punto_idx on public.photos(punto);

alter table public.admins enable row level security;
alter table public.puntos enable row level security;
alter table public.perfiles enable row level security;
alter table public.refs enable row level security;
alter table public.photos enable row level security;

create or replace function public.es_admin() returns boolean
language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.admins where user_id=auth.uid())
$$;
create or replace function public.mi_punto() returns text
language sql stable security definer set search_path=public as $$
  select punto from public.perfiles where user_id=auth.uid() limit 1
$$;

-- Administradores ven todo. Usuarios autenticados solo ven su punto.
drop policy if exists "mi admin" on public.admins;
create policy "mi admin" on public.admins for select to authenticated using (user_id=auth.uid());
drop policy if exists "puntos publicos" on public.puntos;
drop policy if exists "puntos propios o admin" on public.puntos;
create policy "puntos propios o admin" on public.puntos for select to authenticated using (public.es_admin() or nombre=public.mi_punto());
drop policy if exists "admin gestiona puntos" on public.puntos;
create policy "admin gestiona puntos" on public.puntos for all to authenticated using (public.es_admin()) with check (public.es_admin());
drop policy if exists "mi perfil" on public.perfiles;
create policy "mi perfil" on public.perfiles for select to authenticated using (user_id=auth.uid() or public.es_admin());
-- Los clientes anonimos leen el catalogo mediante RPC filtrada por slug. Las tablas no se exponen directamente.
drop policy if exists "lectura publica refs" on public.refs;
drop policy if exists "edicion refs punto" on public.refs;
create policy "edicion refs punto" on public.refs for all to authenticated using (public.es_admin() or punto=public.mi_punto()) with check (public.es_admin() or punto=public.mi_punto());
drop policy if exists "lectura publica fotos" on public.photos;
drop policy if exists "edicion fotos punto" on public.photos;
create policy "edicion fotos punto" on public.photos for all to authenticated using (public.es_admin() or punto=public.mi_punto()) with check (public.es_admin() or punto=public.mi_punto());

insert into storage.buckets(id,name,public) values('fotos','fotos',true) on conflict(id) do update set public=true;
drop policy if exists "admin sube fotos" on storage.objects;
drop policy if exists "admin borra fotos" on storage.objects;
drop policy if exists "ver fotos" on storage.objects; -- el bucket publico permite ver imagenes por URL, pero no listar archivos
create policy "admin sube fotos" on storage.objects for insert to authenticated with check(bucket_id='fotos' and (public.es_admin() or (storage.foldername(name))[1]=(select slug from public.puntos where nombre=public.mi_punto())));
create policy "admin borra fotos" on storage.objects for delete to authenticated using(bucket_id='fotos' and (public.es_admin() or (storage.foldername(name))[1]=(select slug from public.puntos where nombre=public.mi_punto())));

-- Acceso publico seguro: devuelve solo el punto solicitado por su slug, nunca otros catalogos.
create or replace function public.obtener_punto_publico(p_slug text) returns jsonb
language sql stable security definer set search_path=public as $$
  select jsonb_build_object('nombre',p.nombre,'slug',p.slug,'direccion',p.direccion)
  from public.puntos p where p.slug=p_slug limit 1
$$;
create or replace function public.catalogo_publico(p_slug text) returns jsonb
language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'punto',(select jsonb_build_object('nombre',p.nombre,'slug',p.slug,'direccion',p.direccion) from public.puntos p where p.slug=p_slug),
    'refs',coalesce((select jsonb_agg(to_jsonb(r) order by r.pos) from public.refs r join public.puntos p on p.nombre=r.punto where p.slug=p_slug),'[]'::jsonb),
    'photos',coalesce((select jsonb_agg(to_jsonb(ph) order by ph.pos) from public.photos ph join public.puntos p on p.nombre=ph.punto where p.slug=p_slug),'[]'::jsonb)
  )
$$;
revoke execute on function public.obtener_punto_publico(text),public.catalogo_publico(text) from public;
grant execute on function public.obtener_punto_publico(text),public.catalogo_publico(text) to anon,authenticated;

-- Crear punto, usuario de acceso (correo interno basado en slug) y PIN.
create or replace function public.crear_punto(p_nombre text,p_pin text,p_direccion text default '') returns void
language plpgsql security definer set search_path=public,auth,extensions as $$
declare uid uuid:=gen_random_uuid(); n text:=trim(p_nombre); s text; mail text;
begin
  if not public.es_admin() then raise exception 'Solo el administrador puede crear puntos'; end if;
  s:=trim(both '-' from regexp_replace(translate(lower(n),'áéíóúüñ','aeiouun'),'[^a-z0-9]+','-','g'));
  if length(n)<2 or length(n)>60 or length(s)<2 then raise exception 'Nombre invalido (2-60 caracteres)'; end if;
  if length(coalesce(p_pin,''))<4 or length(p_pin)>64 then raise exception 'El PIN debe tener entre 4 y 64 caracteres'; end if;
  mail:=s||'@catalogo.local';
  if exists(select 1 from public.puntos where nombre=n or slug=s) or exists(select 1 from auth.users where email=mail) then raise exception 'Ya existe un punto con ese nombre'; end if;
  insert into public.puntos(nombre,slug,direccion) values(n,s,trim(coalesce(p_direccion,'')));
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,confirmation_token,recovery_token,email_change_token_new,email_change,email_change_token_current,phone_change,phone_change_token,reauthentication_token)
  values('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',mail,crypt(p_pin||'#cat',gen_salt('bf')),now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','','','','','');
  insert into auth.identities(id,user_id,provider_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
  values(gen_random_uuid(),uid,uid::text,jsonb_build_object('sub',uid::text,'email',mail,'email_verified',true),'email',now(),now(),now());
  insert into public.perfiles(user_id,punto) values(uid,n);
end $$;

create or replace function public.cambiar_pin(p_punto text,p_pin text) returns void
language plpgsql security definer set search_path=public,auth,extensions as $$
begin
  if not public.es_admin() then raise exception 'Solo el administrador'; end if;
  if length(coalesce(p_pin,''))<4 or length(p_pin)>64 then raise exception 'El PIN debe tener entre 4 y 64 caracteres'; end if;
  update auth.users set encrypted_password=crypt(p_pin||'#cat',gen_salt('bf')),updated_at=now()
  where id=(select user_id from public.perfiles where punto=p_punto);
  if not found then raise exception 'No se encontro el usuario del punto'; end if;
end $$;

create or replace function public.actualizar_punto(p_punto text,p_nombre text,p_direccion text) returns void
language plpgsql security definer set search_path=public,auth as $$
declare s text; n text:=trim(p_nombre); mail text; uid uuid;
begin
  if not public.es_admin() then raise exception 'Solo el administrador'; end if;
  s:=trim(both '-' from regexp_replace(translate(lower(n),'áéíóúüñ','aeiouun'),'[^a-z0-9]+','-','g'));
  if length(n)<2 or length(n)>60 or length(s)<2 then raise exception 'Nombre invalido'; end if;
  if exists(select 1 from public.puntos where slug=s and nombre<>p_punto) then raise exception 'Ya existe otro punto con ese nombre'; end if;
  mail:=s||'@catalogo.local';
  select user_id into uid from public.perfiles where punto=p_punto;
  if uid is not null and exists(select 1 from auth.users where email=mail and id<>uid) then raise exception 'El identificador del punto ya esta en uso'; end if;
  update public.puntos set nombre=n,slug=s,direccion=trim(coalesce(p_direccion,'')) where nombre=p_punto;
  if uid is not null then
    update auth.users set email=mail,updated_at=now() where id=uid;
    update auth.identities set provider_id=uid::text,identity_data=jsonb_build_object('sub',uid::text,'email',mail,'email_verified',true),updated_at=now() where user_id=uid and provider='email';
  end if;
  update public.perfiles set punto=n where punto=p_punto;
  update public.refs set punto=n where punto=p_punto;
  update public.photos set punto=n where punto=p_punto;
end $$;

create or replace function public.eliminar_punto(p_punto text) returns void
language plpgsql security definer set search_path=public,auth as $$
begin
  if not public.es_admin() then raise exception 'Solo el administrador'; end if;
  delete from auth.users where id in(select user_id from public.perfiles where punto=p_punto);
  delete from public.puntos where nombre=p_punto;
end $$;

revoke execute on function public.crear_punto(text,text,text),public.cambiar_pin(text,text),public.actualizar_punto(text,text,text),public.eliminar_punto(text) from public,anon;
grant execute on function public.crear_punto(text,text,text),public.cambiar_pin(text,text),public.actualizar_punto(text,text,text),public.eliminar_punto(text) to authenticated;

-- El usuario creado previamente en Authentication queda como administrador.
insert into public.admins(user_id) select id from auth.users where email not like '%@catalogo.local' order by created_at asc limit 1 on conflict do nothing;
select u.email as administrador_registrado from auth.users u join public.admins a on a.user_id=u.id;
