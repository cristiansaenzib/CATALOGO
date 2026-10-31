-- Pega TODO esto en Supabase > SQL Editor > Run
create table refs(
  id uuid primary key default gen_random_uuid(),
  parent_id uuid references refs(id) on delete cascade,
  name text not null,
  theme text default 'marfil',
  pos int default 0,
  price_detal text,
  price_dist text,
  price_mayor text
);
create table photos(
  id uuid primary key default gen_random_uuid(),
  ref_id uuid references refs(id) on delete cascade,
  path text not null,
  pos int default 0
);
alter table refs enable row level security;
alter table photos enable row level security;
create policy "ver refs" on refs for select using (true);
create policy "ver photos" on photos for select using (true);
create policy "admin refs" on refs for all to authenticated using (true) with check (true);
create policy "admin photos" on photos for all to authenticated using (true) with check (true);

insert into storage.buckets (id, name, public) values ('fotos','fotos',true);
create policy "ver fotos" on storage.objects for select using (bucket_id='fotos');
create policy "admin sube fotos" on storage.objects for insert to authenticated with check (bucket_id='fotos');
create policy "admin borra fotos" on storage.objects for delete to authenticated using (bucket_id='fotos');
