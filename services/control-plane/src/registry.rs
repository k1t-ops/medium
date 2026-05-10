use overlay_protocol::{
    DeviceCatalogResponse, DeviceRecord, PublishedService, RegisterNodeRequest, ServiceKind,
    SshEndpoint,
};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct RegistryStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub struct ServiceRoute {
    pub node_id: String,
    pub tcp_addr: String,
    pub ice_udp_endpoints: Vec<ServiceEndpoint>,
    pub user_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEndpoint {
    pub addr: String,
    pub priority: i32,
}

impl RegistryStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::migrate!("../../migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn in_memory() -> anyhow::Result<Self> {
        Self::connect("sqlite::memory:").await
    }

    pub async fn register_node(&self, request: &RegisterNodeRequest) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            insert into nodes (id, label)
            values (?1, ?2)
            on conflict(id) do update set
              label = excluded.label,
              updated_at = current_timestamp,
              last_seen_at = current_timestamp
            "#,
        )
        .bind(&request.node_id)
        .bind(&request.node_label)
        .execute(&mut *tx)
        .await?;

        sqlx::query("delete from node_endpoints where node_id = ?1")
            .bind(&request.node_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("delete from node_services where node_id = ?1")
            .bind(&request.node_id)
            .execute(&mut *tx)
            .await?;

        for endpoint in &request.endpoints {
            sqlx::query(
                r#"
                insert into node_endpoints (node_id, kind, schema_version, addr, priority)
                values (?1, ?2, ?3, ?4, ?5)
                "#,
            )
            .bind(&request.node_id)
            .bind(endpoint.kind.as_str())
            .bind(i64::from(endpoint.schema_version))
            .bind(&endpoint.addr)
            .bind(i64::from(endpoint.priority))
            .execute(&mut *tx)
            .await?;
        }

        for service in &request.services {
            sqlx::query(
                r#"
                insert into node_services (id, node_id, kind, schema_version, target, user_name, label)
                values (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
            )
            .bind(&service.id)
            .bind(&request.node_id)
            .bind(service.kind.as_str())
            .bind(i64::from(service.schema_version))
            .bind(&service.target)
            .bind(&service.user_name)
            .bind(&service.label)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn list_devices(&self) -> anyhow::Result<DeviceCatalogResponse> {
        let node_rows = sqlx::query("select id, label from nodes order by id")
            .fetch_all(&self.pool)
            .await?;
        let mut devices = Vec::new();

        for node_row in node_rows {
            let node_id: String = node_row.try_get("id")?;
            let services = self.list_node_services(&node_id).await?;
            let ssh_row = sqlx::query(
                r#"
                select
                  ns.id as service_id,
                  ns.user_name as user_name,
                  ne.addr as endpoint_addr
                from node_services ns
                join node_endpoints ne on ne.node_id = ns.node_id
                where ns.node_id = ?1
                  and ns.kind = 'ssh'
                  and ns.schema_version = 1
                  and ne.kind = 'tcp_proxy'
                  and ne.schema_version = 1
                order by ne.priority desc, ne.id asc, ns.id asc
                limit 1
                "#,
            )
            .bind(&node_id)
            .fetch_optional(&self.pool)
            .await?;

            let ssh = match ssh_row {
                Some(row) => {
                    let endpoint_addr: Option<String> = row.try_get("endpoint_addr")?;
                    match (
                        row.try_get::<Option<String>, _>("service_id")?,
                        row.try_get::<Option<String>, _>("user_name")?,
                        endpoint_addr,
                    ) {
                        (Some(service_id), Some(user_name), Some(addr)) => {
                            let (host, port) = split_addr(&addr)?;
                            Some(SshEndpoint {
                                service_id,
                                host,
                                port,
                                user: user_name,
                            })
                        }
                        _ => None,
                    }
                }
                None => None,
            };

            devices.push(DeviceRecord {
                id: node_id,
                name: node_row.try_get("label")?,
                ssh,
                services,
            });
        }

        Ok(DeviceCatalogResponse { devices })
    }

    async fn list_node_services(&self, node_id: &str) -> anyhow::Result<Vec<PublishedService>> {
        let rows = sqlx::query(
            r#"
            select id, kind, schema_version, target, user_name, label
            from node_services
            where node_id = ?1
            order by id
            "#,
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(PublishedService {
                    id: row.try_get("id")?,
                    kind: parse_service_kind(row.try_get::<String, _>("kind")?)?,
                    schema_version: row.try_get::<i64, _>("schema_version")? as u32,
                    label: row.try_get("label")?,
                    target: row.try_get("target")?,
                    user_name: row.try_get("user_name")?,
                })
            })
            .collect()
    }

    pub async fn resolve_service_route(&self, service_id: &str) -> anyhow::Result<ServiceRoute> {
        let row = sqlx::query(
            r#"
            select
              ns.node_id as node_id,
              ns.user_name as user_name,
              ne.addr as endpoint_addr
            from node_services ns
            join node_endpoints ne on ne.node_id = ns.node_id
            where ns.id = ?1
              and ne.kind = 'tcp_proxy'
              and ne.schema_version = 1
            order by ne.priority desc, ne.id asc
            limit 1
            "#,
        )
        .bind(service_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ServiceRoute {
            node_id: row.try_get("node_id")?,
            tcp_addr: row.try_get("endpoint_addr")?,
            ice_udp_endpoints: self.endpoints(row.try_get("node_id")?, "ice_udp").await?,
            user_name: row.try_get("user_name")?,
        })
    }

    pub async fn resolve_node_service_route(
        &self,
        node_id: &str,
        service_id: &str,
    ) -> anyhow::Result<ServiceRoute> {
        let row = sqlx::query(
            r#"
            select
              ns.node_id as node_id,
              ns.user_name as user_name,
              ne.addr as endpoint_addr
            from node_services ns
            join node_endpoints ne on ne.node_id = ns.node_id
            where ns.node_id = ?1
              and ns.id = ?2
              and ne.kind = 'tcp_proxy'
              and ne.schema_version = 1
            order by ne.priority desc, ne.id asc
            limit 1
            "#,
        )
        .bind(node_id)
        .bind(service_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ServiceRoute {
            node_id: row.try_get("node_id")?,
            tcp_addr: row.try_get("endpoint_addr")?,
            ice_udp_endpoints: self.endpoints(node_id.to_string(), "ice_udp").await?,
            user_name: row.try_get("user_name")?,
        })
    }

    async fn endpoints(&self, node_id: String, kind: &str) -> anyhow::Result<Vec<ServiceEndpoint>> {
        let rows = sqlx::query(
            r#"
            select addr, priority
            from node_endpoints
            where node_id = ?1
              and kind = ?2
              and schema_version = 1
            order by priority desc, id asc
            "#,
        )
        .bind(node_id)
        .bind(kind)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ServiceEndpoint {
                    addr: row.try_get("addr")?,
                    priority: row.try_get::<i64, _>("priority")? as i32,
                })
            })
            .collect()
    }
}

fn split_addr(addr: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid addr {}", addr))?;
    Ok((host.to_string(), port.parse()?))
}

fn parse_service_kind(raw: String) -> anyhow::Result<ServiceKind> {
    match raw.as_str() {
        "http" => Ok(ServiceKind::Http),
        "https" => Ok(ServiceKind::Https),
        "ssh" => Ok(ServiceKind::Ssh),
        _ => anyhow::bail!("unsupported service kind {raw}"),
    }
}
