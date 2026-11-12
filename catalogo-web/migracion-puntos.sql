-- ============================================================
-- PUNTOS DE VENTA: mismo catálogo, fotos distintas por punto
-- Pega TODO esto en Supabase > SQL Editor > Run (una sola vez).
-- Requiere haber corrido antes setup.sql (y migracion-precios.sql si aplica).
-- ============================================================

-- 1) Qué punto de venta tiene cada usuario
create table if not exists perfiles(
  user_id uuid primary key references auth.users(id) on delete cascade,
  punto text not null
);
alter table perfiles enable row level security;
drop policy if exists "ver mi perfil" on perfiles;
create policy "ver mi perfil" on perfiles for select to authenticated using (user_id = auth.uid());
-- (sin políticas de insert/update: los perfiles solo se crean desde el SQL Editor)

-- 2) Cada foto pertenece a un punto
alter table photos add column if not exists punto text;
-- Las fotos que ya existían pasan al Punto 1 (cambia el nombre si quieres):
update photos set punto = 'Punto 1' where punto is null;
alter table photos alter column punto set not null;
create index if not exists photos_punto_idx on photos(punto);

-- 3) Función: punto del usuario que está conectado
create or replace function mi_punto() returns text
language sql stable as $$
  select punto from perfiles where user_id = auth.uid()
$$;

-- 4) Fotos: cada usuario solo ve y modifica las de SU punto
drop policy if exists "ver photos" on photos;
drop policy if exists "admin photos" on photos;
drop policy if exists "fotos del punto: ver" on photos;
drop policy if exists "fotos del punto: crear" on photos;
drop policy if exists "fotos del punto: editar" on photos;
drop policy if exists "fotos del punto: borrar" on photos;
create policy "fotos del punto: ver"    on photos for select to authenticated using (punto = mi_punto());
create policy "fotos del punto: crear"  on photos for insert to authenticated with check (punto = mi_punto());
create policy "fotos del punto: editar" on photos for update to authenticated using (punto = mi_punto()) with check (punto = mi_punto());
create policy "fotos del punto: borrar" on photos for delete to authenticated using (punto = mi_punto());

-- 5) Referencias, sub-referencias y precios: ahora solo con sesión iniciada
--    (la política "admin refs" ya permite todo a usuarios autenticados)
drop policy if exists "ver refs" on refs;

-- ============================================================
-- 6) ASIGNAR USUARIOS A SU PUNTO
-- Primero crea los 2 usuarios en Authentication > Users (correo + contraseña).
-- Luego cambia los correos y nombres de abajo y ejecuta estas 2 líneas:
-- ============================================================
insert into perfiles(user_id, punto) select id, 'Punto 1' from auth.users where email = 'punto1@tucorreo.com'
  on conflict (user_id) do update set punto = excluded.punto;
insert into perfiles(user_id, punto) select id, 'Punto 2' from auth.users where email = 'punto2@tucorreo.com'
  on conflict (user_id) do update set punto = excluded.punto;
