create table if not exists node_services_scoped (
  id text not null,
  node_id text not null references nodes(id) on delete cascade,
  kind text not null,
  schema_version integer not null,
  target text not null,
  user_name text,
  label text,
  created_at text not null default current_timestamp,
  primary key (node_id, id)
);

insert into node_services_scoped (id, node_id, kind, schema_version, target, user_name, label, created_at)
select id, node_id, kind, schema_version, target, user_name, label, created_at
from node_services;

drop table node_services;

alter table node_services_scoped rename to node_services;
