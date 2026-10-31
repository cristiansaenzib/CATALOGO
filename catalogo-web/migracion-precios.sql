-- SOLO si ya habias corrido setup.sql antes: pega esto en Supabase > SQL Editor > Run
alter table refs add column if not exists price_detal text;
alter table refs add column if not exists price_dist text;
alter table refs add column if not exists price_mayor text;
