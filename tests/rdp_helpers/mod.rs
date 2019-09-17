pub mod test_server;

use std::{net::{IpAddr, Ipv4Addr}, io};

use serde::{Serialize, Deserialize};

const TLS_PUBLIC_KEY_HEADER: usize = 24;
const CLIENT_IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const CERT_PKCS12_PASS: &str = "password";
const MCS_INITIATOR_ID: u16 = 1001;
const MCS_IO_CHANNEL_ID: u16 = 1003;
const MCS_STATIC_CHANNELS_START_ID: u16 = 1004;
const SHARE_ID: u32 = 66_538;
const SERVER_PDU_SOURCE: u16 = 0x03ea;

#[derive(Clone, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: sspi::Credentials,
    pub target: sspi::Credentials,
    pub destination: String,
}

impl RdpIdentity {
    pub fn new(proxy: sspi::Credentials, target: sspi::Credentials, destination: String) -> Self {
        Self {
            proxy,
            target,
            destination,
        }
    }

    pub fn list_to_buffer(rdp_identities: &[Self], mut file: impl io::Write) {
        let identities_buffer = serde_json::to_string(&rdp_identities).expect("failed to convert identities to json");
        file.write_all(identities_buffer.as_bytes())
            .expect("failed to write identities to file");
    }
}

#[derive(Clone)]
pub struct IdentitiesProxy {
    rdp_identity: sspi::Credentials,
}

impl IdentitiesProxy {
    pub fn new(rdp_identity: sspi::Credentials) -> Self {
        Self { rdp_identity }
    }
}

impl sspi::CredentialsProxy for IdentitiesProxy {
    fn password_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<String> {
        assert_eq!(username, self.rdp_identity.username);
        assert_eq!(domain, self.rdp_identity.domain);

        Ok(self.rdp_identity.password.clone())
    }
}
