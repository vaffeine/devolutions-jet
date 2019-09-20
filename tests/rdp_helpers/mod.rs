pub mod test_client;
pub mod test_server;

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr},
};

use bytes::BytesMut;
use ironrdp::PduParsing;
use serde::{Deserialize, Serialize};

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

fn process_cred_ssp_phase_with_reply_needed(
    ts_request: sspi::TsRequest,
    cred_ssp_context: &mut impl sspi::CredSsp,
    tls_stream: &mut (impl io::Write + io::Read),
) {
    let reply = cred_ssp_context
        .process(ts_request)
        .expect("failed to process CredSSP phase");
    match reply {
        sspi::CredSspResult::ReplyNeeded(ts_request) => {
            let mut ts_request_buffer = Vec::with_capacity(ts_request.buffer_len() as usize);
            ts_request
                .encode_ts_request(&mut ts_request_buffer)
                .expect("failed to encode TSRequest");

            tls_stream
                .write_all(&ts_request_buffer)
                .expect("failed to send CredSSP message");
        }
        _ => panic!("the CredSSP server has returned unexpected result: {:?}", reply),
    }
}

fn read_x224_data_pdu<T>(buffer: &mut BytesMut) -> T
where
    T: ironrdp::PduParsing,
    T::Error: fmt::Debug,
{
    let data_pdu = ironrdp::Data::from_buffer(buffer.as_ref()).expect("failed to read X224 Data");
    buffer.split_to(data_pdu.buffer_length() - data_pdu.data_length);
    let pdu = T::from_buffer(buffer.as_ref()).expect("failed to decode X224 Data");
    buffer.split_to(data_pdu.data_length);

    pdu
}

fn write_x224_data_pdu<T>(pdu: T, mut stream: impl io::Write)
where
    T: ironrdp::PduParsing,
    T::Error: fmt::Debug,
{
    ironrdp::Data::new(pdu.buffer_length())
        .to_buffer(&mut stream)
        .expect("failed to write X224 Data");
    pdu.to_buffer(&mut stream).expect("failed to encode X224 Data");
}

fn read_finalization_pdu(
    mut buffer: &mut BytesMut,
    expected_initiator_id: u16,
    expected_channel_id: u16,
) -> ironrdp::rdp::ShareDataPdu {
    let share_control_header =
        read_send_data_context_pdu::<ironrdp::ShareControlHeader>(&mut buffer, expected_initiator_id, expected_channel_id);
    if share_control_header.share_id != SHARE_ID {
        panic!(
            "Got unexpected Share ID for Finalization PDU: {} != {}",
            SHARE_ID, share_control_header.share_id
        );
    }

    if let ironrdp::rdp::ShareControlPdu::Data(ironrdp::rdp::ShareDataHeader {
        share_data_pdu,
        compression_flags,
        ..
    }) = share_control_header.share_control_pdu
    {
        if compression_flags != ironrdp::rdp::CompressionFlags::empty() {
            panic!(
                "Unexpected Compression Flags in Share Data Header PDU for Finalization PDU: {:?}",
                compression_flags
            );
        }

        share_data_pdu
    } else {
        panic!(
            "Got unexpected Share Control PDU while was expected Data with Finalization PDU: {:?}",
            share_control_header.share_control_pdu
        );
    }
}

fn write_finalization_pdu(
    pdu: ironrdp::rdp::ShareDataPdu,
    initiator_id: u16,
    channel_id: u16,
    mut stream: impl io::Write,
) {
    let share_data_header = ironrdp::rdp::ShareDataHeader::new(
        pdu,
        ironrdp::rdp::StreamPriority::Medium,
        ironrdp::rdp::CompressionFlags::empty(),
        ironrdp::rdp::CompressionType::K8,
    );

    let share_control_header = ironrdp::rdp::ShareControlHeader::new(
        ironrdp::rdp::ShareControlPdu::Data(share_data_header),
        SERVER_PDU_SOURCE,
        SHARE_ID,
    );
    write_send_data_context_pdu(share_control_header, initiator_id, channel_id, &mut stream);
}

fn read_send_data_context_pdu<T>(mut buffer: &mut BytesMut, expected_initiator_id: u16, expected_channel_id: u16) -> T
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    match read_x224_data_pdu::<ironrdp::McsPdu>(&mut buffer) {
        ironrdp::mcs::McsPdu::SendDataRequest(send_data_context) => {
            if send_data_context.initiator_id != expected_initiator_id {
                panic!(
                    "Unexpected Send Data Context PDU initiator ID: {} != {}",
                    expected_initiator_id, send_data_context.initiator_id
                );
            }
            if send_data_context.channel_id != expected_channel_id {
                panic!(
                    "Unexpected Send Data Context PDU channel ID: {} != {}",
                    expected_channel_id, send_data_context.channel_id
                );
            }

            T::from_buffer(send_data_context.pdu.as_slice()).expect("failed to decode Send Data Context PDU")
        }
        pdu => panic!(
            "Got unexpected MCS PDU, while was expected Channel Join Confirm PDU: {:?}",
            pdu
        ),
    }
}

fn write_send_data_context_pdu<T>(pdu: T, initiator_id: u16, channel_id: u16, mut stream: impl io::Write)
where
    T: PduParsing,
    T::Error: fmt::Debug,
{
    let mut pdu_buffer = Vec::with_capacity(pdu.buffer_length());
    pdu.to_buffer(&mut pdu_buffer)
        .expect("failed to encode Send Data Context PDU");

    let send_data_context_pdu = ironrdp::SendDataContext::new(pdu_buffer, initiator_id, channel_id);

    write_x224_data_pdu(ironrdp::McsPdu::SendDataIndication(send_data_context_pdu), &mut stream);
}
