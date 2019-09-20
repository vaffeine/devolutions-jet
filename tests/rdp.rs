mod rdp_helpers;
mod common;

use std::{
    process::{Child, Command},
    thread,
    time::Duration,
};

use lazy_static::lazy_static;

use rdp_helpers::{
    RdpIdentity, IdentitiesProxy,
    test_server::RdpServer,
};
use common::run_proxy;

lazy_static! {
    static ref PROXY_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("ProxyUserName"),
        String::from("ProxyPassword"),
        Some(String::from("ProxyDomainName")),
    );
    static ref SERVER_CREDENTIALS: sspi::Credentials = sspi::Credentials::new(
        String::from("TargetServerUserName"),
        String::from("TargetServerPassword"),
        Some(String::from("TargetServerDomainName")),
    );
    static ref CERT_PKCS12_DER: Vec<u8> = include_bytes!("../src/cert/certificate.p12").to_vec();
}

const IRONRDP_CLIENT_PATH: &str = "ironrdp_client";
const JET_PROXY_SERVER_ADDR: &str = "127.0.0.1:8080";
const TARGET_SERVER_ADDR: &str = "127.0.0.1:8081";
const DEVOLUTIONS_IDENTITIES_SERVER_URL: &str = "rdp://127.0.0.1:8082";

fn run_client() -> Child {
    let mut client_command = Command::new(IRONRDP_CLIENT_PATH);
    client_command
        .arg(JET_PROXY_SERVER_ADDR)
        .args(&["--security_protocol", "hybrid"])
        .args(&["--username", PROXY_CREDENTIALS.username.as_str()])
        .args(&["--password", PROXY_CREDENTIALS.password.as_str()]);

    client_command.spawn().expect("failed to run IronRDP client") }

#[test]
fn rdp_with_nla_ntlm() {
    let mut identities_file = tempfile::NamedTempFile::new().expect("failed to create a named temporary file");
    let rdp_identities = vec![RdpIdentity::new(
        PROXY_CREDENTIALS.clone(),
        SERVER_CREDENTIALS.clone(),
        TARGET_SERVER_ADDR.to_string(),
    )];
    RdpIdentity::list_to_buffer(rdp_identities.as_ref(), identities_file.as_file_mut());

    let _proxy = run_proxy(
        JET_PROXY_SERVER_ADDR,
        Some(DEVOLUTIONS_IDENTITIES_SERVER_URL),
        Some(
            identities_file
                .path()
                .to_str()
                .expect("failed to get path to a temporary file"),
        ),
    );
    thread::sleep(Duration::from_millis(500));

    let server_thread = thread::spawn(move || {
        let mut server = RdpServer::new(TARGET_SERVER_ADDR, IdentitiesProxy::new(SERVER_CREDENTIALS.clone()));
        server.run();
    });
    let client_thread = thread::spawn(move || {
        let mut client = run_client();
        client.wait().expect("error occurred in IronRDP client");
    });

    client_thread.join().expect("failed to join the client thread");
    server_thread.join().expect("failed to join the server thread");
}
