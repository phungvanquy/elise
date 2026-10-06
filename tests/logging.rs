use std::fs;
use std::process::Command;

#[test]
fn runtime_file_survives_initialization_and_panel_errors_are_redacted() {
    let dir = std::env::temp_dir().join(format!("elise-logging-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // A refused connection makes reqwest include the credential-bearing URL.
    drop(listener);
    let config = dir.join("elise.conf");
    let log = dir.join("runtime.log");
    fs::write(&config, format!("type=v2board\npanel_url=http://{addr}\npanel_key=LOG_SECRET+&?#\nnode_id=1\nlog_level=info\nlog_file={}\nnodes_dir={}/nodes\nip_user_cache_save_dir={}/state\npprof_addr=off\nauto_tls=false\n", log.display(), dir.display(), dir.display())).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_elise"))
        .args(["run", "-c"])
        .arg(config)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(!result.status.success());
    for text in [
        String::from_utf8_lossy(&result.stderr).into_owned(),
        fs::read_to_string(&log).unwrap(),
    ] {
        assert!(text.contains("Starting Elise"), "{text}");
        assert!(text.contains("Failed to fetch node info"), "{text}");
        assert!(!text.contains("LOG_SECRET"), "{text}");
        assert!(!text.contains('\u{1b}'));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn security_debug_output_never_includes_key_material() {
    use elise::transport::types::{
        MlkemConfig, RealityServerConfig, TransportSecurityConfig, VlessEncryptionConfig,
    };
    let reality = TransportSecurityConfig::Reality(RealityServerConfig {
        dest: "example.com:443".into(),
        server_names: vec!["example.com".into()],
        private_key: [123; 32],
        short_ids: vec![vec![42]],
        xver: 0,
        max_time_diff_ms: 0,
        min_client_ver: None,
        max_client_ver: None,
        spider_x: None,
    });
    let encryption = VlessEncryptionConfig::Mlkem768X25519Plus(MlkemConfig {
        xor_mode: 0,
        seconds_from: 0,
        seconds_to: 0,
        server_padding: None,
        server_keys: vec![vec![123; 32]],
    });
    for text in [format!("{reality:?}"), format!("{encryption:?}")] {
        assert!(!text.contains("123"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("server_keys"));
        assert!(!text.contains("short_ids"));
    }
}
