-- Ejecuta una sola vez en Supabase SQL Editor para habilitar el QR por punto de venta.
alter table public.puntos add column if not exists qr_path text;

create or replace function public.obtener_punto_publico(p_slug text) returns jsonb
language sql stable security definer set search_path=public as $$
  select jsonb_build_object('nombre',p.nombre,'slug',p.slug,'direccion',p.direccion,'qr_path',p.qr_path)
  from public.puntos p where p.slug=p_slug limit 1
$$;

create or replace function public.catalogo_publico(p_slug text) returns jsonb
language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'punto',(select jsonb_build_object('nombre',p.nombre,'slug',p.slug,'direccion',p.direccion,'qr_path',p.qr_path) from public.puntos p where p.slug=p_slug),
    'refs',coalesce((select jsonb_agg(to_jsonb(r) order by r.pos) from public.refs r join public.puntos p on p.nombre=r.punto where p.slug=p_slug),'[]'::jsonb),
    'photos',coalesce((select jsonb_agg(to_jsonb(ph) order by ph.pos) from public.photos ph join public.puntos p on p.nombre=ph.punto where p.slug=p_slug),'[]'::jsonb)
  )
$$;
revoke execute on function public.obtener_punto_publico(text),public.catalogo_publico(text) from public;
grant execute on function public.obtener_punto_publico(text),public.catalogo_publico(text) to anon,authenticated;
