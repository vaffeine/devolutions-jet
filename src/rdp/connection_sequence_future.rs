use std::io;

use futures::{try_ready, Future};
use ironrdp::nego;
use tokio::{
    codec::{Decoder, Framed},
    prelude::*,
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_tcp::{ConnectFuture, TcpStream};

use crate::{
    rdp::{
        filter::FilterConfig,
        identities_proxy::{IdentitiesProxy, RdpIdentity},
        sequence_future::{
            create_negotiation_request, GetStateArgs, McsFuture, McsFutureTransport, McsInitialFuture,
            NegotiationWithClientFuture, NegotiationWithServerFuture, NlaTransport, NlaWithClientFuture,
            NlaWithServerFuture, PostMcs, SendStateArgs, SequenceFuture, StaticChannels,
        },
    },
    transport::{
        mcs::McsTransport,
        x224::{DataTransport, NegotiationWithClientTransport, NegotiationWithServerTransport},
    },
    utils,
};

pub struct ConnectionSequenceFuture {
    state: ConnectionSequenceFutureState,
    client_nla_transport: Option<NlaTransport>,
    tls_proxy_pubkey: Option<Vec<u8>>,
    tls_acceptor: Option<TlsAcceptor>,
    identities_proxy: IdentitiesProxy,
    request: Option<nego::Request>,
    response_protocol: Option<nego::SecurityProtocol>,
    rdp_identity: Option<RdpIdentity>,
    filter_config: Option<FilterConfig>,
    joined_static_channels: Option<StaticChannels>,
}

impl ConnectionSequenceFuture {
    pub fn new(
        client: TcpStream,
        tls_proxy_pubkey: Vec<u8>,
        tls_acceptor: TlsAcceptor,
        identities_proxy: IdentitiesProxy,
    ) -> Self {
        Self {
            state: ConnectionSequenceFutureState::NegotiationWithClient(Box::new(SequenceFuture::with_get_state(
                NegotiationWithClientFuture::new(),
                GetStateArgs {
                    client: Some(NegotiationWithClientTransport::default().framed(client)),
                    server: None,
                },
            ))),
            client_nla_transport: None,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            tls_acceptor: Some(tls_acceptor),
            identities_proxy,
            request: None,
            response_protocol: None,
            rdp_identity: None,
            filter_config: None,
            joined_static_channels: None,
        }
    }

    fn create_nla_client_future(
        &mut self,
        client: TcpStream,
        client_response_protocol: nego::SecurityProtocol,
    ) -> NlaWithClientFuture {
        NlaWithClientFuture::new(
            client,
            client_response_protocol,
            self.tls_proxy_pubkey
                .take()
                .expect("TLS proxy public key must be set in the constructor"),
            self.identities_proxy.clone(),
            self.tls_acceptor
                .take()
                .expect("TLS acceptor must be set in the constructor"),
        )
    }
    fn create_connect_server_future(&self) -> io::Result<ConnectFuture> {
        let destination = self
            .rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation")
            .destination
            .clone();
        let destination_addr = destination.parse().map_err(move |e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid target destination ({}): {}", destination, e),
            )
        })?;

        Ok(TcpStream::connect(&destination_addr))
    }
    fn create_server_negotiation_future(
        &mut self,
        server: TcpStream,
    ) -> io::Result<SequenceFuture<NegotiationWithServerFuture, TcpStream, NegotiationWithServerTransport>> {
        let server_transport = NegotiationWithServerTransport::default().framed(server);

        let target_username = self.rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation and be taken by reference in the connect server state")
            .target
            .username
            .clone();
        let pdu = create_negotiation_request(
            target_username,
            self.request
                .as_ref()
                .expect("For server negotiation future, the request must be set after negotiation with client")
                .clone(),
        )?;

        Ok(SequenceFuture::with_send_state(
            NegotiationWithServerFuture::new(),
            SendStateArgs {
                send_future: server_transport.send(pdu),
            },
        ))
    }
    fn create_nla_server_future(
        &self,
        server: TcpStream,
        server_response_protocol: nego::SecurityProtocol,
    ) -> io::Result<NlaWithServerFuture> {
        let target_identity = self.rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation and be taken by reference in the server negotiation state").target.clone().into();
        let request_flags = self
            .request
            .as_ref()
            .expect("for NLA server future, the request must be set after negotiation with client")
            .flags;

        NlaWithServerFuture::new(server, request_flags, server_response_protocol, target_identity, true)
    }
    fn create_mcs_initial_future(
        &mut self,
        server_nla_transport: NlaTransport,
    ) -> SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, DataTransport> {
        let client_nla_transport = self
            .client_nla_transport
            .take()
            .expect("For the McsInitial state, the client NLA transport must be set after the client negotiation");
        let client_transport = match client_nla_transport {
            NlaTransport::TsRequest(transport) => utils::update_framed_codec(transport, DataTransport::default()),
            NlaTransport::EarlyUserAuthResult(transport) => {
                utils::update_framed_codec(transport, DataTransport::default())
            }
        };
        let server_transport = match server_nla_transport {
            NlaTransport::TsRequest(transport) => utils::update_framed_codec(transport, DataTransport::default()),
            NlaTransport::EarlyUserAuthResult(transport) => {
                utils::update_framed_codec(transport, DataTransport::default())
            }
        };

        let response_protocol = self
            .response_protocol
            .expect("Response protocol must be set in NegotiationWithServer future");
        let target = self
            .rdp_identity
            .as_ref()
            .expect("the RDP identity must be set after the server NLA")
            .target
            .clone()
            .into();

        SequenceFuture::with_get_state(
            McsInitialFuture::new(FilterConfig::new(response_protocol, target)),
            GetStateArgs {
                client: Some(client_transport),
                server: Some(server_transport),
            },
        )
    }
    fn create_mcs_future(
        &mut self,
        client_mcs_initial_transport: Framed<TlsStream<TcpStream>, DataTransport>,
        server_mcs_initial_transport: Framed<TlsStream<TcpStream>, DataTransport>,
        static_channels: StaticChannels,
    ) -> SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport> {
        SequenceFuture::with_get_state(
            McsFuture::new(static_channels),
            GetStateArgs {
                client: Some(utils::update_framed_codec(
                    client_mcs_initial_transport,
                    McsTransport::default(),
                )),
                server: Some(utils::update_framed_codec(
                    server_mcs_initial_transport,
                    McsTransport::default(),
                )),
            },
        )
    }
    fn create_rdp_future(
        &mut self,
        client_transport: McsFutureTransport,
        server_transport: McsFutureTransport,
    ) -> SequenceFuture<PostMcs, TlsStream<TcpStream>, McsTransport> {
        SequenceFuture::with_get_state(
            PostMcs::new(
                self.filter_config
                    .take()
                    .expect("the filter config must be set after the MCS initial"),
            ),
            GetStateArgs {
                client: Some(client_transport),
                server: Some(server_transport),
            },
        )
    }
}

impl Future for ConnectionSequenceFuture {
    type Item = (TlsStream<TcpStream>, TlsStream<TcpStream>, StaticChannels);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &mut self.state {
                ConnectionSequenceFutureState::NegotiationWithClient(negotiation_future) => {
                    let (transport, request, response) = try_ready!(negotiation_future.poll());
                    self.request = Some(request);

                    let client = transport.into_inner();

                    if let Some(nego::ResponseData::Response { protocol, .. }) = response.response {
                        self.state = ConnectionSequenceFutureState::NlaWithClient(Box::new(
                            self.create_nla_client_future(client, protocol),
                        ));
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "The client does not support HYBRID (or HYBRID_EX) protocol",
                        ));
                    }
                }
                ConnectionSequenceFutureState::NlaWithClient(nla_future) => {
                    let (client_transport, rdp_identity) = try_ready!(nla_future.poll());
                    self.client_nla_transport = Some(client_transport);
                    self.rdp_identity = Some(rdp_identity);

                    self.state = ConnectionSequenceFutureState::ConnectToServer(self.create_connect_server_future()?);
                }
                ConnectionSequenceFutureState::ConnectToServer(connect_future) => {
                    let server = try_ready!(connect_future.poll());

                    self.state = ConnectionSequenceFutureState::NegotiationWithServer(Box::new(
                        self.create_server_negotiation_future(server)?,
                    ));
                }
                ConnectionSequenceFutureState::NegotiationWithServer(negotiation_future) => {
                    let (server_transport, response) = try_ready!(negotiation_future.poll());

                    let server = server_transport.into_inner();

                    if let Some(nego::ResponseData::Response { protocol, .. }) = response.response {
                        self.response_protocol = Some(protocol);
                        self.state = ConnectionSequenceFutureState::NlaWithServer(Box::new(
                            self.create_nla_server_future(server, protocol)?,
                        ));
                    } else {
                        unreachable!("The negotiation with client future must return response");
                    }
                }
                ConnectionSequenceFutureState::NlaWithServer(nla_future) => {
                    let server_nla_transport = try_ready!(nla_future.poll());

                    self.state = ConnectionSequenceFutureState::McsInitial(Box::new(
                        self.create_mcs_initial_future(server_nla_transport),
                    ))
                }
                ConnectionSequenceFutureState::McsInitial(mcs_initial_future) => {
                    let (client_transport, server_transport, filter_config, static_channels) =
                        try_ready!(mcs_initial_future.poll());
                    self.filter_config = Some(filter_config);

                    self.state = ConnectionSequenceFutureState::Mcs(Box::new(self.create_mcs_future(
                        client_transport,
                        server_transport,
                        static_channels,
                    )));
                }
                ConnectionSequenceFutureState::Mcs(mcs_future) => {
                    let (client_transport, server_transport, joined_static_channels) = try_ready!(mcs_future.poll());
                    self.joined_static_channels = Some(joined_static_channels);

                    self.state = ConnectionSequenceFutureState::PostMcs(Box::new(
                        self.create_rdp_future(client_transport, server_transport),
                    ));
                }
                ConnectionSequenceFutureState::PostMcs(rdp_future) => {
                    let (client_transport, server_transport, _filter_config) = try_ready!(rdp_future.poll());

                    let client_tls = client_transport.into_inner();
                    let server_tls = server_transport.into_inner();

                    return Ok(Async::Ready((
                        client_tls,
                        server_tls,
                        self.joined_static_channels.take().expect(
                            "During RDP connection sequence, the joined static channels must exist in the RDP state",
                        ),
                    )));
                }
            }
        }
    }
}

enum ConnectionSequenceFutureState {
    NegotiationWithClient(Box<SequenceFuture<NegotiationWithClientFuture, TcpStream, NegotiationWithClientTransport>>),
    NlaWithClient(Box<NlaWithClientFuture>),
    ConnectToServer(ConnectFuture),
    NegotiationWithServer(Box<SequenceFuture<NegotiationWithServerFuture, TcpStream, NegotiationWithServerTransport>>),
    NlaWithServer(Box<NlaWithServerFuture>),
    McsInitial(Box<SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, DataTransport>>),
    Mcs(Box<SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport>>),
    PostMcs(Box<SequenceFuture<PostMcs, TlsStream<TcpStream>, McsTransport>>),
}
