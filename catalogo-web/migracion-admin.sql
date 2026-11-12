-- ============================================================
-- ADMIN + CATALOGOS APARTE POR PUNTO + USUARIOS CON PIN
-- Pega TODO en Supabase > SQL Editor > Run (una sola vez).
-- Requiere haber corrido antes setup.sql y migracion-puntos.sql.
-- Los nombres de punto deben coincidir con PUNTOS en index.html.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

-- 1) Perfiles: rol (admin / punto)
alter table perfiles add column if not exists rol text not null default 'punto';

-- 2) Cada referencia/sub-referencia pertenece a un punto (catalogos aparte)
alter table refs add column if not exists punto text;
do $$ begin
  if exists (select 1 from refs where punto is null) then
    -- copia el arbol de referencias para 'Punto 2' y mueve alli las fotos de ese punto
    create temp table mapa on commit drop as select id as viejo, gen_random_uuid() as nuevo from refs where punto is null;
    insert into refs(id,parent_id,name,theme,pos,price_detal,price_dist,price_mayor,punto)
      select m.nuevo, mp.nuevo, r.name, r.theme, r.pos, r.price_detal, r.price_dist, r.price_mayor, 'Punto 2'
      from refs r join mapa m on m.viejo=r.id left join mapa mp on mp.viejo=r.parent_id;
    update photos set ref_id=m.nuevo from mapa m where photos.ref_id=m.viejo and photos.punto='Punto 2';
    update refs set punto='Punto 1' where punto is null;
  end if;
end $$;
alter table refs alter column punto set not null;
create index if not exists refs_punto_idx on refs(punto);

-- 3) Funciones de apoyo
create or replace function es_admin() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from perfiles where user_id=auth.uid() and rol='admin') $$;
create or replace function mi_punto() returns text language sql stable security definer set search_path=public as
$$ select punto from perfiles where user_id=auth.uid() $$;

-- 4) Permisos: el admin ve y modifica todo; cada punto solo lo suyo
drop policy if exists "admin refs" on refs;
drop policy if exists "refs del punto" on refs;
create policy "refs del punto" on refs for all to authenticated
  using (es_admin() or punto=mi_punto()) with check (es_admin() or punto=mi_punto());
drop policy if exists "fotos del punto: ver" on photos;
drop policy if exists "fotos del punto: crear" on photos;
drop policy if exists "fotos del punto: editar" on photos;
drop policy if exists "fotos del punto: borrar" on photos;
create policy "fotos del punto: ver" on photos for select to authenticated using (es_admin() or punto=mi_punto());
create policy "fotos del punto: crear" on photos for insert to authenticated with check (es_admin() or punto=mi_punto());
create policy "fotos del punto: editar" on photos for update to authenticated using (es_admin() or punto=mi_punto()) with check (es_admin() or punto=mi_punto());
create policy "fotos del punto: borrar" on photos for delete to authenticated using (es_admin() or punto=mi_punto());
drop policy if exists "admin ve perfiles" on perfiles;
create policy "admin ve perfiles" on perfiles for select to authenticated using (es_admin());

-- 5) Usuarios con PIN (usuario -> correo interno usuario@catalogo.local; clave = PIN || '#cat')
create or replace function crear_usuario(p_usuario text, p_pin text, p_punto text, p_rol text default 'punto')
returns uuid language plpgsql security definer set search_path=public,auth,extensions as $$
declare uid uuid := gen_random_uuid(); mail text; u text := lower(trim(p_usuario));
begin
  if auth.role() in ('anon','authenticated') and not es_admin() then raise exception 'Solo el administrador'; end if;
  if u !~ '^[a-z0-9._-]{3,30}$' then raise exception 'Usuario: 3-30 letras/numeros (sin espacios)'; end if;
  if length(coalesce(p_pin,''))<4 then raise exception 'El PIN debe tener minimo 4 caracteres'; end if;
  if p_rol not in ('admin','punto') then raise exception 'Rol invalido'; end if;
  mail := u||'@catalogo.local';
  if exists(select 1 from auth.users where email=mail) then raise exception 'Ese usuario ya existe'; end if;
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,
    confirmation_token,recovery_token,email_change_token_new,email_change,email_change_token_current,phone_change,phone_change_token,reauthentication_token)
  values('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',mail,crypt(p_pin||'#cat',gen_salt('bf')),now(),
    '{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','','','','','');
  insert into auth.identities(id,user_id,provider_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
  values(gen_random_uuid(),uid,uid::text,jsonb_build_object('sub',uid::text,'email',mail,'email_verified',true),'email',now(),now(),now());
  insert into perfiles(user_id,punto,rol) values(uid,p_punto,p_rol);
  return uid;
end $$;

create or replace function cambiar_pin(p_user uuid, p_pin text) returns void
language plpgsql security definer set search_path=public,auth,extensions as $$
begin
  if not es_admin() then raise exception 'Solo el administrador'; end if;
  if length(coalesce(p_pin,''))<4 then raise exception 'El PIN debe tener minimo 4 caracteres'; end if;
  update auth.users set encrypted_password=crypt(p_pin||'#cat',gen_salt('bf')), updated_at=now() where id=p_user;
end $$;

create or replace function eliminar_usuario(p_user uuid) returns void
language plpgsql security definer set search_path=public,auth as $$
begin
  if not es_admin() then raise exception 'Solo el administrador'; end if;
  if p_user=auth.uid() then raise exception 'No puedes eliminarte a ti mismo'; end if;
  delete from auth.users where id=p_user;
end $$;

create or replace function listar_usuarios() returns table(user_id uuid, usuario text, punto text, rol text)
language plpgsql stable security definer set search_path=public,auth as $$
begin
  if not es_admin() then raise exception 'Solo el administrador'; end if;
  return query select p.user_id, case when u.email like '%@catalogo.local' then split_part(u.email,'@',1) else u.email end, p.punto, p.rol
    from perfiles p join auth.users u on u.id=p.user_id order by p.rol, p.punto, 2;
end $$;

revoke execute on function crear_usuario, cambiar_pin, eliminar_usuario, listar_usuarios from public, anon;
grant execute on function crear_usuario, cambiar_pin, eliminar_usuario, listar_usuarios to authenticated;

-- 6) PRIMER ADMINISTRADOR: cambia 'admin' y el PIN antes de ejecutar (luego crea los demas desde la web)
select crear_usuario('admin','CAMBIAME-1234','Punto 1','admin');
-- Si prefieres convertir un usuario que ya existe en admin, en vez de la linea anterior:
-- update perfiles set rol='admin' where user_id=(select id from auth.users where email='tucorreo@mail.com');
