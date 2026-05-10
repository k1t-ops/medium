use overlay_protocol::{
    EndpointKind, NodeEndpoint, PublishedService, RegisterNodeRequest, ServiceKind,
};

#[tokio::test]
async fn registry_returns_devices_from_registered_nodes() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "127.0.0.1:17001".into(),
                priority: 10,
            }],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: Some("Node SSH".into()),
                target: "127.0.0.1:2222".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();

    let catalog = store.list_devices().await.unwrap();

    assert_eq!(catalog.devices.len(), 1);
    assert_eq!(catalog.devices[0].name, "Node");
    assert_eq!(
        catalog.devices[0].ssh.as_ref().unwrap().service_id,
        "svc_ssh"
    );
    assert_eq!(catalog.devices[0].ssh.as_ref().unwrap().port, 17001);
    assert_eq!(catalog.devices[0].ssh.as_ref().unwrap().user, "overlay");
    assert_eq!(catalog.devices[0].services.len(), 1);
    assert_eq!(catalog.devices[0].services[0].id, "svc_ssh");
    assert_eq!(catalog.devices[0].services[0].kind, ServiceKind::Ssh);
    assert_eq!(
        catalog.devices[0].services[0].label.as_deref(),
        Some("Node SSH")
    );
    assert_eq!(catalog.devices[0].services[0].target, "127.0.0.1:2222");
}

#[tokio::test]
async fn registry_returns_all_published_services_for_phone_clients() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "office-server".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "127.0.0.1:17001".into(),
                priority: 100,
            }],
            services: vec![
                PublishedService {
                    id: "svc_openclaw".into(),
                    kind: ServiceKind::Https,
                    schema_version: 1,
                    label: Some("OpenClaw".into()),
                    target: "127.0.0.1:3000".into(),
                    user_name: None,
                },
                PublishedService {
                    id: "svc_api".into(),
                    kind: ServiceKind::Http,
                    schema_version: 1,
                    label: Some("HTTP API".into()),
                    target: "127.0.0.1:8081".into(),
                    user_name: None,
                },
            ],
        })
        .await
        .unwrap();

    let catalog = store.list_devices().await.unwrap();

    assert_eq!(catalog.devices.len(), 1);
    assert_eq!(catalog.devices[0].name, "office-server");
    assert!(catalog.devices[0].ssh.is_none());
    assert_eq!(catalog.devices[0].services.len(), 2);
    assert_eq!(catalog.devices[0].services[0].id, "svc_api");
    assert_eq!(catalog.devices[0].services[0].kind, ServiceKind::Http);
    assert_eq!(
        catalog.devices[0].services[0].label.as_deref(),
        Some("HTTP API")
    );
    assert_eq!(catalog.devices[0].services[1].id, "svc_openclaw");
    assert_eq!(
        catalog.devices[0].services[1].label.as_deref(),
        Some("OpenClaw")
    );
}

#[tokio::test]
async fn registry_resolves_service_route_for_session_open() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "127.0.0.1:17001".into(),
                priority: 10,
            }],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: Some("Node SSH".into()),
                target: "127.0.0.1:2222".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();

    let route = store.resolve_service_route("svc_ssh").await.unwrap();

    assert_eq!(route.node_id, "node-1");
    assert_eq!(route.tcp_addr, "127.0.0.1:17001");
    assert_eq!(route.user_name.as_deref(), Some("overlay"));
}

#[tokio::test]
async fn registry_scopes_service_ids_by_node_for_default_ssh_services() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node 1".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "127.0.0.1:17001".into(),
                priority: 10,
            }],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: None,
                target: "127.0.0.1:22".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "studio-smiley".into(),
            node_label: "studio-smiley".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "192.168.1.126:17001".into(),
                priority: 10,
            }],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: None,
                target: "127.0.0.1:22".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();

    let route = store
        .resolve_node_service_route("studio-smiley", "svc_ssh")
        .await
        .unwrap();

    assert_eq!(route.node_id, "studio-smiley");
    assert_eq!(route.tcp_addr, "192.168.1.126:17001");
    assert_eq!(route.user_name.as_deref(), Some("overlay"));
}
