use std::{
    fmt,
    io::{self, Write},
    net::TcpStream,
    thread,
    time::Duration,
};

use bytes::BytesMut;
use native_tls::TlsStream;
use sspi::CredSsp;

// TODO: remove
#[allow(unused_imports)]
use super::{
    process_cred_ssp_phase_with_reply_needed, read_finalization_pdu, read_send_data_context_pdu, read_x224_data_pdu,
    write_finalization_pdu, write_send_data_context_pdu, write_x224_data_pdu, IdentitiesProxy, CERT_PKCS12_PASS,
    CLIENT_IP_ADDR, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, MCS_STATIC_CHANNELS_START_ID, SERVER_PDU_SOURCE, SHARE_ID,
    TLS_PUBLIC_KEY_HEADER,
};

struct RdpClient {
    proxy_addr: &'static str,
    proxy_credentials: sspi::Credentials,
    server_credentials: sspi::Credentials,
}

impl RdpClient {
    fn new(
        proxy_addr: &'static str,
        proxy_credentials: sspi::Credentials,
        server_credentials: sspi::Credentials,
    ) -> Self {
        Self {
            proxy_addr,
            proxy_credentials,
            server_credentials,
        }
    }

    fn run(&self) {
        let mut stream = connect_tcp_stream(self.proxy_addr);
        self.x224(&mut stream);

        let mut tls_stream = connect_tls(self.proxy_addr, stream, true);
        self.nla(&mut tls_stream);
        self.mcs(&mut tls_stream);
        self.write_client_info(&mut tls_stream);
        self.read_server_no_license_response(&mut tls_stream);
        self.capabilities_exchange(&mut tls_stream);
        self.finalization(&mut tls_stream);

        // TODO: remove
        thread::sleep(std::time::Duration::from_millis(1000));
    }

    fn x224(&self, mut stream: &mut TcpStream) {
        self.write_negotiation_request(&mut stream);
        self.read_negotiation_response(&mut stream);
    }

    fn nla(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        let tls_pubkey = get_tls_peer_pubkey(&tls_stream).unwrap();
        let mut cred_ssp_context = sspi::CredSspClient::with_default_version(
            tls_pubkey,
            self.proxy_credentials.clone(),
            sspi::CredSspMode::WithCredentials,
        )
        .unwrap();

        self.write_negotiate_message(&mut tls_stream, &mut cred_ssp_context);

        let buffer = read_stream_buffer(&mut tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref()).unwrap();
        process_cred_ssp_phase_with_reply_needed(read_ts_request, &mut cred_ssp_context, tls_stream);

        self.read_pub_key_auth_and_write_ts_credentials(&mut tls_stream, &mut cred_ssp_context);
    }

    fn mcs(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        self.write_mcs_initial_request(&mut tls_stream);
        self.read_mcs_initial_response(&mut tls_stream);
        self.write_mcs_erect_domain_request(&mut tls_stream);
        self.write_mcs_attach_user_request(&mut tls_stream);
        self.read_mcs_attach_user_confirm(&mut tls_stream);
        self.process_mcs_channel_joins(&mut tls_stream);
    }

    fn capabilities_exchange(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        self.read_server_demand_active(&mut tls_stream);
        self.write_client_confirm_active(&mut tls_stream);
    }

    fn finalization(&self, mut tls_stream: &mut TlsStream<TcpStream>) {
        self.write_synchronize_pdu(&mut tls_stream);
        self.read_synchronize_pdu(&mut tls_stream);
        self.write_control_pdu_cooperate(&mut tls_stream);
        self.read_control_cooperate_pdu(&mut tls_stream);
        self.write_control_pdu_request_control(&mut tls_stream);
        self.read_control_response_pdu(&mut tls_stream);
        self.write_font_list_pdu(&mut tls_stream);
        self.read_font_map_pdu(&mut tls_stream);
    }

    fn read_font_map_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            ShareDataPdu::FontMap(_) => (),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Font Map PDU: {:?}",
                share_data_pdu,
            ),
        }
    }

    fn read_synchronize_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            ShareDataPdu::Synchronize(_) => (),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Synchronize: {:?}",
                share_data_pdu,
            ),
        }
    }

    fn read_control_cooperate_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            ShareDataPdu::Control(c) => assert_eq!(c.action, ControlAction::Cooperate),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Control: {:?}",
                share_data_pdu,
            ),
        }
    }

    fn read_control_response_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let share_data_pdu = read_finalization_pdu(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        match share_data_pdu {
            ShareDataPdu::Control(c) => assert_eq!(c.action, ControlAction::GrantedControl),
            _ => panic!(
                "Unexpected Finalization PDU while was expected Control: {:?}",
                share_data_pdu,
            ),
        }
    }

    fn write_synchronize_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ShareDataPdu::Synchronize(SynchronizePdu::new(0x03ea));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, tls_stream);
    }

    fn write_control_pdu_cooperate(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ShareDataPdu::Control(ControlPdu::new(ControlAction::Cooperate, 0, 0));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_control_pdu_request_control(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ShareDataPdu::Control(ControlPdu::new(ControlAction::RequestControl, 0, 0));
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_font_list_pdu(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let pdu = ShareDataPdu::FontList(FontPdu {
            number: 0,
            total_number: 0,
            flags: SequenceFlags::FIRST | SequenceFlags::LAST,
            entry_size: 50,
        });
        write_finalization_pdu(pdu, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn write_client_confirm_active(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let confirm_active = ClientConfirmActive {
            pdu: DemandActive {
                source_descriptor: String::from("MSTSC"),
                capability_sets: vec![
                    CapabilitySet::General(capability_sets::General {
                        major_platform_type: capability_sets::MajorPlatformType::Unspecified,
                        minor_platform_type: capability_sets::MinorPlatformType::Unspecified,
                        extra_flags: capability_sets::GeneralExtraFlags::all(),
                        refresh_rect_support: true,
                        suppress_output_support: true,
                    }),
                    CapabilitySet::Bitmap(capability_sets::Bitmap {
                        pref_bits_per_pix: 4,
                        desktop_width: 1920,
                        desktop_height: 1080,
                        desktop_resize_flag: true,
                        drawing_flags: capability_sets::BitmapDrawingFlags::all(),
                    }),
                    CapabilitySet::Order(capability_sets::Order::new(
                        capability_sets::OrderFlags::all(),
                        capability_sets::OrderSupportExFlags::all(),
                        480 * 480,
                        0,
                    )),
                    CapabilitySet::Pointer(capability_sets::Pointer {
                        color_pointer_cache_size: 25,
                        pointer_cache_size: 25,
                    }),
                    CapabilitySet::Input(capability_sets::Input {
                        input_flags: capability_sets::InputFlags::all(),
                        keyboard_layout: 0,
                        keyboard_type: None,
                        keyboard_subtype: 0,
                        keyboard_function_key: 0,
                        keyboard_ime_filename: String::new(),
                    }),
                    CapabilitySet::VirtualChannel(capability_sets::VirtualChannel {
                        flags: capability_sets::VirtualChannelFlags::COMPRESSION_CLIENT_TO_SERVER_8K,
                        chunk_size: 16256,
                    }),
                ],
            },
        };

        let pdu = ShareControlPdu::ClientConfirmActive(confirm_active);
        let header = ShareControlHeader::new(pdu, SERVER_PDU_SOURCE, SHARE_ID);
        write_send_data_context_pdu(header, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID, &mut tls_stream);
    }

    fn read_server_demand_active(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let mut share_control_header =
            read_send_data_context_pdu::<ShareControlHeader>(&mut buffer, MCS_INITIATOR_ID, MCS_IO_CHANNEL_ID);

        if let ShareControlPdu::ServerDemandActive(demand_active) = share_control_header.share_control_pdu {
            // apply filter that works on a proxy side
            sent_struct
                .pdu
                .capability_sets
                .retain(|capability_set| match capability_set {
                    capability_sets::CapabilitySet::BitmapCacheHostSupport(_)
                    | capability_sets::CapabilitySet::Control(_)
                    | capability_sets::CapabilitySet::WindowActivation(_)
                    | capability_sets::CapabilitySet::Share(_)
                    | capability_sets::CapabilitySet::Font(_)
                    | capability_sets::CapabilitySet::MultiFragmentUpdate(_)
                    | capability_sets::CapabilitySet::LargePointer(_)
                    | capability_sets::CapabilitySet::DesktopComposition(_) => false,
                    _ => true,
                });
        }
    }

    fn read_server_no_license_response(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let response: McsPdu = read_mcs_pdu(&mut buffer).unwrap();
        assert_eq!(response, McsBuilder::build_license_error_pdu_valid_client());
    }

    fn write_client_info(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let request: McsPdu = McsBuilder::build_client_info_pdu();

        write_x224_data_pdu(request, tls_stream).unwrap();
    }

    fn process_mcs_channel_joins(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let network_data = McsBuilder::build_mcs_connect_response()
            .conference_create_response
            .gcc_blocks
            .network;
        let mut channel_ids = network_data.channel_ids;
        channel_ids.push(network_data.io_channel);
        channel_ids.push(
            McsBuilder::build_mcs_connect_response()
                .conference_create_response
                .user_id,
        );

        for id in &channel_ids {
            self.write_mcs_channel_join_request(*id, tls_stream).unwrap();

            self.read_mcs_channel_join_confirm(*id, tls_stream).unwrap();
        }
    }

    fn read_mcs_channel_join_confirm(&self, channel_id: u16, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);

        let response: McsPdu = read_mcs_pdu(&mut buffer).unwrap();

        assert_eq!(response, McsBuilder::build_mcs_channel_join_confirm(channel_id));
    }

    fn write_mcs_channel_join_request(&self, channel_id: u16, tls_stream: &mut TlsStream<TcpStream>) {
        let request: McsPdu = McsBuilder::build_mcs_channel_join_request(channel_id);

        write_x224_data_pdu(request, tls_stream).unwrap();
    }

    fn read_mcs_attach_user_confirm(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let response: McsPdu = read_mcs_pdu(&mut buffer).unwrap();
        assert_eq!(response, McsBuilder::build_mcs_attach_user_confirm());
    }

    fn write_mcs_attach_user_request(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let request: McsPdu = McsBuilder::build_mcs_attach_user_request();
        write_x224_data_pdu(request, tls_stream).unwrap();
    }

    fn write_mcs_erect_domain_request(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let request: McsPdu = McsBuilder::build_mcs_erect_domain_request();
        write_x224_data_pdu(request, tls_stream).unwrap();;
    }

    fn read_mcs_initial_response(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let mut buffer = read_stream_buffer(tls_stream);
        let response: ConnectResponse = read_mcs_pdu(&mut buffer).unwrap();

        // apply filter that works on a proxy side
        let mut server_original_response = McsBuilder::build_mcs_connect_response();
        let mut gcc_blocks = &mut server_original_response.conference_create_response.gcc_blocks;
        gcc_blocks.multi_transport_channel = None;
        gcc_blocks.message_channel = None;

        assert_eq!(response, server_original_response);
    }

    fn write_mcs_initial_request(&self, tls_stream: &mut TlsStream<TcpStream>) {
        let request: ironrdp::ConnectInitial = McsBuilder::build_mcs_connect_request();
        write_x224_data_pdu(request, tls_stream).unwrap();
    }

    fn write_negotiation_request(&self, stream: &mut TcpStream) {
        let cookie = &self.server_credentials.username;
        let mut request_data = BytesMut::with_capacity(ironrdp::NEGOTIATION_REQUEST_LEN + cookie.len());
        request_data.resize(ironrdp::NEGOTIATION_REQUEST_LEN + cookie.len(), 0x00);
        ironrdp::write_negotiation_request(
            request_data.as_mut(),
            &cookie,
            *X224_REQUEST_PROTOCOL,
            *X224_REQUEST_FLAGS,
        )
        .unwrap();
        let x224_len = ironrdp::TPDU_REQUEST_LENGTH + request_data.len();
        let mut x224_encoded_request = BytesMut::with_capacity(x224_len);
        x224_encoded_request.resize(ironrdp::TPDU_REQUEST_LENGTH, 0);
        ironrdp::encode_x224(
            ironrdp::X224TPDUType::ConnectionRequest,
            request_data,
            &mut x224_encoded_request,
        )
        .unwrap();

        stream.write_all(x224_encoded_request.as_ref()).unwrap();
    }

    fn read_negotiation_response(&self, mut stream: &mut TcpStream) {
        let mut buffer = read_stream_buffer(&mut stream);
        let (code, data) = ironrdp::decode_x224(&mut buffer).unwrap();
        assert_eq!(code, ironrdp::X224TPDUType::ConnectionConfirm);
        let (protocol, flags) = ironrdp::parse_negotiation_response(code, data.as_ref()).unwrap();
        assert_eq!(*X224_RESPONSE_PROTOCOL, protocol);
        assert_eq!(*X224_RESPONSE_FLAGS, flags);
    }

    fn write_negotiate_message(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspClient,
    ) {
        process_cred_ssp_phase_with_reply_needed(sspi::TsRequest::default(), cred_ssp_context, tls_stream).unwrap();
    }

    fn read_pub_key_auth_and_write_ts_credentials(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        cred_ssp_context: &mut sspi::CredSspClient,
    ) {
        let buffer = read_stream_buffer(tls_stream);
        let read_ts_request = sspi::TsRequest::from_buffer(buffer.as_ref()).unwrap();

        let reply = cred_ssp_context.process(read_ts_request).unwrap();
        match reply {
            sspi::CredSspResult::FinalMessage(ts_request) => {
                let mut ts_request_buffer = Vec::with_capacity(ts_request.buffer_len() as usize);
                ts_request.encode_ts_request(&mut ts_request_buffer).unwrap();

                tls_stream.write_all(&ts_request_buffer).unwrap();
            }
            _ => panic!("The CredSSP server has returned unexpected result: {:?}", reply),
        };
    }
}

fn connect_tcp_stream(addr: &str) -> TcpStream {
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            // TODO: remove
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn connect_tls<S>(addr: &str, stream: S, accept_invalid_certs_and_hostnames: bool) -> TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + 'static,
{
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(accept_invalid_certs_and_hostnames)
        .danger_accept_invalid_hostnames(accept_invalid_certs_and_hostnames)
        .build()
        .unwrap();

    tls_connector.connect(addr, stream).unwrap()
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
            // TODO: remove this fucking shit
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn get_tls_peer_pubkey<S>(stream: &TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    let der = stream
        .peer_certificate()
        .expect("failed to get peer certificate")
        .unwrap()
        .to_der()
        .unwrap();
    let cert = openssl::x509::X509::from_der(&der)?;

    let tls_pubkey_size = 24;
    Ok(cert.public_key()?.public_key_to_der()?.split_off(tls_pubkey_size))
}
