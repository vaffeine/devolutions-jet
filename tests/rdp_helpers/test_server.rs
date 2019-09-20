use std::{
    fmt,
    io::{self, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use bytes::BytesMut;
use ironrdp::{
    gcc, mcs,
    nego::{Request, Response, ResponseData, ResponseFlags, SecurityProtocol},
    rdp::{self, capability_sets},
    ClientConfirmActive, ClientInfoPdu, ConnectInitial, ConnectResponse, McsPdu, PduParsing, ServerDemandActive,
    ServerLicensePdu,
};
use native_tls::{TlsAcceptor, TlsStream};
use sspi::CredSsp;

use super::{
    process_cred_ssp_phase_with_reply_needed, read_finalization_pdu, read_send_data_context_pdu, read_x224_data_pdu,
    write_finalization_pdu, write_send_data_context_pdu, write_x224_data_pdu, IdentitiesProxy, CERT_PKCS12_PASS,
    CLIENT_IP_ADDR, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, MCS_STATIC_CHANNELS_START_ID, SERVER_PDU_SOURCE, SHARE_ID,
    TLS_PUBLIC_KEY_HEADER,
};
use crate::{CERT_PKCS12_DER, SERVER_CREDENTIALS};

pub struct RdpServer {
    routing_addr: &'static str,
    identities_proxy: IdentitiesProxy,
}

impl RdpServer {
    pub fn new(routing_addr: &'static str, identities_proxy: IdentitiesProxy) -> Self {
        Self {
            routing_addr,
            identities_proxy,
        }
    }

    pub fn run(&mut self) {
        let mut stream = accept_tcp_stream(self.routing_addr);
        self.x224(&mut stream);

        let mut tls_stream = accept_tls(stream, CERT_PKCS12_DER.clone(), CERT_PKCS12_PASS);
        self.nla(&mut tls_stream);

        let client_color_depth = self.mcs(&mut tls_stream);

        self.read_client_info(&mut tls_stream);
        self.write_server_no_license_response(&mut tls_stream);

        let client_pdu_source = self.capabilities_exchange(&mut tls_stream, client_color_depth);

        self.finalization(&mut tls_stream, client_pdu_source);
    }

    fn x224(&self, mut stream: &mut TcpStream) {
        self.read_negotiation_request(&mut stream);
        self.write_negotiation_response(&mut stream);
    }

    fn nla(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let tls_pubkey = get_tls_pubkey(CERT_PKCS12_DER.clone().as_ref(), CERT_PKCS12_PASS);

        let mut cred_ssp_context = sspi::CredSspServer::with_default_version(tls_pubkey, self.identities_proxy.clone())
            .expect("failed to create a CredSSP server");

        self.read_negotiate_message_and_write_challenge_message(&mut tls_stream, &mut cred_ssp_context);
        self.read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth(&mut tls_stream, &mut cred_ssp_context);
        self.read_ts_credentials(&mut tls_stream, &mut cred_ssp_context);
    }

    fn mcs(&self, mut tls_stream: &mut TlsStream<TcpStream>) -> gcc::ClientColorDepth {
        let (channel_names, client_color_depth) = self.read_mcs_connect_initial(&mut tls_stream);
        let channel_ids = self.write_mcs_connect_response(&mut tls_stream, channel_names.as_ref());
        self.read_mcs_erect_domain_request(&mut tls_stream);
        self.read_mcs_attach_user_request(&mut tls_stream);
        self.write_mcs_attach_user_confirm(&mut tls_stream);
        self.process_mcs_channel_joins(&mut tls_stream, channel_ids);

        client_color_depth
    }

    fn capabilities_exchange(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
        client_color_depth: gcc::ClientColorDepth,
    ) -> u16 {
        self.write_demand_active(&mut tls_stream, client_color_depth);

        self.read_confirm_active(&mut tls_stream)
    }

    fn finalization(&self, mut tls_stream: &mut TlsStream<TcpStream>, client_pdu_source: u16) {
        self.read_synchronize_pdu(&mut tls_stream);
        self.write_synchronize_pdu(&mut tls_stream, client_pdu_source);
        self.read_control_pdu_cooperate(&mut tls_stream);
        self.write_control_pdu_cooperate(&mut tls_stream);
        self.read_request_control_pdu(&mut tls_stream);
        self.write_granted_control_pdu(&mut tls_stream);
        self.read_font_list(&mut tls_stream);
        self.write_font_map(&mut tls_stream);
    }

    fn read_negotiation_request(&self, stream: &mut TcpStream) {
        let buffer = read_stream_buffer(stream);
        let _request = Request::from_buffer(buffer.as_ref());
    }

    fn write_negotiation_response(&self, stream: &mut TcpStream) {
        let response = Response {
            response: Some(ResponseData::Response {
                flags: ResponseFlags::all(),
                protocol: SecurityProtocol::HYBRID,
            }),
            dst_ref: 0,
            src_ref: 0,
        };

        let mut response_buffer = BytesMut::with_capacity(response.buffer_length());
        response_buffer.resize(response.buffer_length(), 0x00);
        response
            .to_buffer(response_buffer.as_mut())
            .expect("failed to write negotiation response");

        stream
            .write_all(response_buffer.as_ref())
            .expect("failed to send negotiation response");
    }

    fn read_negotiate_message_and_write_challenge_message<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse TSRequest with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_authenticate_message_with_pub_key_auth_and_write_pub_key_auth<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with NTLM negotiate message");

        process_cred_ssp_phase_with_reply_needed(read_ts_request, cred_ssp_context, tls_stream);
    }

    fn read_ts_credentials<C: sspi::CredentialsProxy>(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspServer<C>,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref())
            .expect("failed to parse ts request with ntlm negotiate message");

        let reply = cred_ssp_context
            .process(read_ts_request)
            .expect("failed to parse NTLM authenticate message and write pub key auth");
        match reply {
            sspi::CredSspResult::ClientCredentials(ref client_credentials) => {
                let expected_credentials = &self.identities_proxy.rdp_identity;
                assert_eq!(expected_credentials, client_credentials);
            }
            _ => panic!("the CredSSP server has returned unexpected result: {:?}", reply),
        };
    }

    fn read_mcs_connect_initial(&self, stream: &mut TlsStream<TcpStream>) -> (Vec<String>, gcc::ClientColorDepth) {
        let mut buffer = read_stream_buffer(stream);
        let connect_initial = read_x224_data_pdu::<ConnectInitial>(&mut buffer);

        // check that jet removed specific fields
        let gcc_blocks = connect_initial.conference_create_request.gcc_blocks;
        assert_eq!(gcc_blocks.core.version, gcc::RdpVersion::V5Plus);
        assert_eq!(
            gcc_blocks.core.optional_data.early_capability_flags,
            Some(gcc::ClientEarlyCapabilityFlags::empty())
        );
        assert_eq!(gcc_blocks.security, gcc::ClientSecurityData::no_security());
        assert!(gcc_blocks.cluster.is_none());
        assert!(gcc_blocks.monitor.is_none());
        assert!(gcc_blocks.monitor_extended.is_none());
        assert!(gcc_blocks.multi_transport_channel.is_none());
        assert!(gcc_blocks.message_channel.is_none());

        let channels = gcc_blocks.channel_names().iter().map(|v| v.name.clone()).collect();

        (channels, gcc_blocks.core.client_color_depth())
    }

    fn write_mcs_connect_response(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
        channel_names: &[String],
    ) -> Vec<u16> {
        let channel_ids = (MCS_STATIC_CHANNELS_START_ID..MCS_STATIC_CHANNELS_START_ID + channel_names.len() as u16)
            .collect::<Vec<_>>();
        let connection_response = ConnectResponse {
            conference_create_response: gcc::ConferenceCreateResponse {
                user_id: MCS_INITIATOR_ID,
                gcc_blocks: gcc::ServerGccBlocks {
                    core: gcc::ServerCoreData {
                        version: gcc::RdpVersion::V10_1,
                        optional_data: gcc::ServerCoreOptionalData {
                            client_requested_protocols: Some(SecurityProtocol::HYBRID),
                            early_capability_flags: Some(gcc::ServerEarlyCapabilityFlags::all()),
                        },
                    },
                    network: gcc::ServerNetworkData {
                        io_channel: MCS_IO_CHANNEL_ID,
                        channel_ids: channel_ids.clone(),
                    },
                    security: gcc::ServerSecurityData::no_security(),
                    message_channel: None,
                    multi_transport_channel: None,
                },
            },
            called_connect_id: 1,
            domain_parameters: mcs::DomainParameters::target(),
        };
        write_x224_data_pdu(connection_response, &mut tls_stream);

        channel_ids
    }

    fn read_mcs_erect_domain_request(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::ErectDomainRequest(_) => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn read_mcs_attach_user_request(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(&mut tls_stream);
        match read_x224_data_pdu::<McsPdu>(&mut buffer) {
            McsPdu::AttachUserRequest => (),
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        };
    }

    fn write_mcs_attach_user_confirm(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let attach_user_confirm = McsPdu::AttachUserConfirm(mcs::AttachUserConfirmPdu {
            initiator_id: MCS_INITIATOR_ID,
            result: 1,
        });
        write_x224_data_pdu(attach_user_confirm, &mut tls_stream);
    }

    fn read_mcs_channel_join_request(&self, stream: &mut TlsStream<TcpStream>) -> u16 {
        let mut buffer = read_stream_buffer(stream);
        let mcs_pdu = read_x224_data_pdu(&mut buffer);
        match mcs_pdu {
            McsPdu::ChannelJoinRequest(mcs::ChannelJoinRequestPdu {
                initiator_id,
                channel_id,
            }) => {
                assert_eq!(MCS_INITIATOR_ID, initiator_id);

                channel_id
            }
            pdu => panic!("Got unexpected MCS PDU: {:?}", pdu),
        }
    }

    fn write_mcs_channel_join_confirm(&self, channel_id: u16, mut tls_stream: &mut TlsStream<TcpStream>) {
        let channel_join_confirm = McsPdu::ChannelJoinConfirm(mcs::ChannelJoinConfirmPdu {
            channel_id,
            result: 1,
            initiator_id: MCS_INITIATOR_ID,
            requested_channel_id: channel_id,
        });
        write_x224_data_pdu(channel_join_confirm, &mut tls_stream);
    }

    fn process_mcs_channel_joins(&self, mut tls_stream: &mut TlsStream<TcpStream>, gcc_channel_ids: Vec<u16>) {
        let mut ids = gcc_channel_ids;
        ids.extend_from_slice(&[MCS_IO_CHANNEL_ID, MCS_INITIATOR_ID]);

        while !ids.is_empty() {
            let channel_id = self.read_mcs_channel_join_request(tls_stream);
            ids.retain(|&v| v != channel_id);
            self.write_mcs_channel_join_confirm(channel_id, &mut tls_stream);
        }
    }

    fn read_client_info(&self, stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(stream);
        let client_info = read_send_data_context_pdu::<ClientInfoPdu>(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        let expected_address_family = match CLIENT_IP_ADDR {
            IpAddr::V4(_) => rdp::AddressFamily::INet,
            IpAddr::V6(_) => rdp::AddressFamily::INet6,
        };
        let expected_address = CLIENT_IP_ADDR.to_string();

        assert_eq!(client_info.client_info.credentials, *SERVER_CREDENTIALS);
        assert_eq!(
            client_info.client_info.extra_info.address_family,
            expected_address_family
        );
        assert_eq!(client_info.client_info.extra_info.address, expected_address);
    }

    fn write_server_no_license_response(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ServerLicensePdu {
            security_header: rdp::BasicSecurityHeader {
                flags: rdp::BasicSecurityHeaderFlags::LICENSE_PKT,
            },
            server_license: rdp::ServerLicense {
                preamble: rdp::LicensePreamble {
                    message_type: rdp::PreambleType::ErrorAlert,
                    flags: rdp::PreambleFlags::empty(),
                    version: rdp::PreambleVersion::V3,
                },
                error_message: rdp::LicensingErrorMessage {
                    error_code: rdp::LicensingErrorCode::StatusValidClient,
                    state_transition: rdp::LicensingStateTransition::NoTransition,
                    error_info: rdp::LicensingBinaryBlob {
                        blob_type: rdp::BlobType::Error,
                        data: Vec::new(),
                    },
                },
            },
        };
        write_send_data_context_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_demand_active(
        &self,
        mut tls_stream: &mut TlsStream<TcpStream>,
        client_color_depth: gcc::ClientColorDepth,
    ) {
        let pref_bits_per_pix = match client_color_depth {
            gcc::ClientColorDepth::Bpp4 => 4,
            gcc::ClientColorDepth::Bpp8 => 8,
            gcc::ClientColorDepth::Rgb555Bpp16 | gcc::ClientColorDepth::Rgb565Bpp16 => 16,
            gcc::ClientColorDepth::Bpp24 => 24,
            gcc::ClientColorDepth::Bpp32 => 32,
        };
        let demand_active = ServerDemandActive {
            pdu: rdp::DemandActive {
                source_descriptor: String::from("RDP"),
                capability_sets: vec![
                    rdp::CapabilitySet::General(capability_sets::General {
                        major_platform_type: capability_sets::MajorPlatformType::Unspecified,
                        minor_platform_type: capability_sets::MinorPlatformType::Unspecified,
                        extra_flags: capability_sets::GeneralExtraFlags::all(),
                        refresh_rect_support: true,
                        suppress_output_support: true,
                    }),
                    rdp::CapabilitySet::Bitmap(capability_sets::Bitmap {
                        pref_bits_per_pix,
                        desktop_width: 1920,
                        desktop_height: 1080,
                        desktop_resize_flag: true,
                        drawing_flags: capability_sets::BitmapDrawingFlags::all(),
                    }),
                    rdp::CapabilitySet::Order(capability_sets::Order::new(
                        capability_sets::OrderFlags::all(),
                        capability_sets::OrderSupportExFlags::all(),
                        480 * 480,
                        0,
                    )),
                    rdp::CapabilitySet::Pointer(capability_sets::Pointer {
                        color_pointer_cache_size: 25,
                        pointer_cache_size: 25,
                    }),
                    rdp::CapabilitySet::Input(capability_sets::Input {
                        input_flags: capability_sets::InputFlags::all(),
                        keyboard_layout: 0,
                        keyboard_type: None,
                        keyboard_subtype: 0,
                        keyboard_function_key: 0,
                        keyboard_ime_filename: String::new(),
                    }),
                    rdp::CapabilitySet::VirtualChannel(capability_sets::VirtualChannel {
                        flags: capability_sets::VirtualChannelFlags::COMPRESSION_CLIENT_TO_SERVER_8K,
                        chunk_size: 16256,
                    }),
                ],
            },
        };
        let pdu = rdp::ShareControlPdu::ServerDemandActive(demand_active);
        let header = rdp::ShareControlHeader::new(pdu, SERVER_PDU_SOURCE, SHARE_ID);
        write_send_data_context_pdu(header, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_confirm_active(&self, tls_stream: &mut TlsStream<TcpStream>) -> u16 {
        let mut buffer = read_stream_buffer(tls_stream);
        let mut share_control_header =
            read_send_data_context_pdu::<rdp::ShareControlHeader>(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);
        if share_control_header.share_id != SHARE_ID {
            panic!(
                "Unexpected Client Confirm Active Share Control Header PDU share ID: {} != {}",
                SHARE_ID, share_control_header.share_id
            );
        }

        if let rdp::ShareControlPdu::ClientConfirmActive(ClientConfirmActive { ref mut pdu }) =
            share_control_header.share_control_pdu
        {
            let size = pdu.capability_sets.len();
            pdu.capability_sets.retain(|capability_set| match capability_set {
                rdp::CapabilitySet::BitmapCacheHostSupport(_)
                | rdp::CapabilitySet::Control(_)
                | rdp::CapabilitySet::WindowActivation(_)
                | rdp::CapabilitySet::Share(_)
                | rdp::CapabilitySet::Font(_)
                | rdp::CapabilitySet::LargePointer(_)
                | rdp::CapabilitySet::DesktopComposition(_) => false,
                _ => true,
            });
            if size != pdu.capability_sets.len() {
                panic!("The Jet did not filter qualitatively capability sets");
            }

            share_control_header.pdu_source
        } else {
            panic!(
                "Got unexpected Share Control PDU while was expected Client Confirm Active PDU: {:?}",
                share_control_header.share_control_pdu
            );
        }
    }

    fn read_synchronize_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Synchronize(rdp::SynchronizePdu { target_user_id }) = share_data_pdu {
            if target_user_id != MCS_INITIATOR_ID {
                panic!(
                    "Got unexpected target user ID in Synchronize PDU: {} != {}",
                    MCS_INITIATOR_ID, target_user_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Synchronize PDU: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_synchronize_pdu(&self, mut tls_stream: &mut TlsStream<TcpStream>, client_pdu_source: u16) {
        let pdu = rdp::ShareDataPdu::Synchronize(rdp::SynchronizePdu::new(client_pdu_source));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_control_pdu_cooperate(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action,
            grant_id,
            control_id,
        }) = share_data_pdu
        {
            if action != rdp::ControlAction::Cooperate {
                panic!("Expected Control Cooperate PDU, got Control {:?} PDU", action);
            }
            if grant_id != 0 || control_id != 0 {
                panic!(
                    "Control Cooperate PDU grant ID and control ID must be set to zero: {} != 0 or {} != 0",
                    grant_id, control_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Control PDU - Cooperate: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_control_pdu_cooperate(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu::new(rdp::ControlAction::Cooperate, 0, 0));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_request_control_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let rdp::ShareDataPdu::Control(rdp::ControlPdu {
            action,
            grant_id,
            control_id,
        }) = share_data_pdu
        {
            if action != rdp::ControlAction::RequestControl {
                panic!("Expected Control Request Control PDU, got Control {:?} PDU", action);
            }
            if grant_id != 0 || control_id != 0 {
                panic!(
                    "Control Request Control PDU grant ID and control ID must be set to zero: {} != 0 or {} != 0",
                    grant_id, control_id
                );
            }
        } else {
            panic!(
                "Unexpected Finalization PDU while was expected Control PDU - Request Control: {:?}",
                share_data_pdu
            );
        }
    }

    fn write_granted_control_pdu(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::Control(rdp::ControlPdu::new(
            rdp::ControlAction::GrantedControl,
            MCS_INITIATOR_ID,
            u32::from(SERVER_PDU_SOURCE),
        ));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_font_list(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            rdp::ShareDataPdu::FontList(_) => (),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Font List PDU: {:?}",
                share_data_pdu
            ),
        }
    }

    fn write_font_map(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = rdp::ShareDataPdu::FontMap(rdp::FontPdu::new(
            0,
            0,
            rdp::SequenceFlags::FIRST | rdp::SequenceFlags::LAST,
            4,
        ));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }
}

fn read_stream_buffer(stream: &mut impl io::Read) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(1024);
    buffer.resize(1024, 0u8);
    loop {
        match stream.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);

                return buffer;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn accept_tcp_stream(addr: &str) -> TcpStream {
    let listener_addr = addr.parse::<SocketAddr>().expect("failed to parse an addr");
    let listener = TcpListener::bind(&listener_addr).expect("failed to bind to stream");
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => return stream,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn accept_tls<S>(stream: S, cert_pkcs12_der: Vec<u8>, cert_pass: &str) -> TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + 'static,
{
    let cert = native_tls::Identity::from_pkcs12(cert_pkcs12_der.as_ref(), cert_pass).unwrap();
    let tls_acceptor = TlsAcceptor::builder(cert)
        .build()
        .expect("failed to create TlsAcceptor");

    tls_acceptor
        .accept(stream)
        .expect("failed to accept the SSL connection")
}

pub fn get_tls_pubkey(der: &[u8], pass: &str) -> Vec<u8> {
    let cert = openssl::pkcs12::Pkcs12::from_der(der)
        .expect("failed to get PKCS12 from DER")
        .parse(pass)
        .expect("failed to parse PKCS12 DER")
        .cert;

    get_tls_pubkey_from_cert(cert)
}

fn get_tls_pubkey_from_cert(cert: openssl::x509::X509) -> Vec<u8> {
    cert.public_key()
        .expect("failed to get public key from cert")
        .public_key_to_der()
        .expect("failed to convert public key to DER")
        .split_off(TLS_PUBLIC_KEY_HEADER)
}
