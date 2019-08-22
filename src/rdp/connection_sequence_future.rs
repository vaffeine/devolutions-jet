use std::io;

use futures::{try_ready, Future};
use ironrdp::nego;
use tokio::{codec::Decoder, prelude::*};
use tokio_tcp::{ConnectFuture, TcpStream};
use tokio_tls::{TlsAcceptor, TlsStream};

use crate::{
    rdp::{
        filter::FilterConfig,
        identities_proxy::{IdentitiesProxy, RdpIdentity},
        sequence_future::{
            create_negotiation_request, GetStateArgs, McsFuture, McsFutureTransport, McsInitialFuture,
            NegotiationWithClientFuture, NegotiationWithServerFuture, NlaWithClientFuture, NlaWithServerFuture,
            PostMcs, SendStateArgs, SequenceFuture, StaticChannels,
        },
    },
    transport::{
        mcs::McsTransport,
        x224::{DataTransport, NegotiationWithClientTransport, NegotiationWithServerTransport},
    },
};

pub struct ConnectionSequenceFuture {
    state: ConnectionSequenceFutureState,
    client_tls: Option<TlsStream<TcpStream>>,
    tls_proxy_pubkey: Option<Vec<u8>>,
    tls_acceptor: Option<TlsAcceptor>,
    identities_proxy: Option<IdentitiesProxy>,
    request: Option<nego::Request>,
    rdp_identity: Option<RdpIdentity>,
    filter_config: Option<FilterConfig>,
    joined_static_channels: Option<StaticChannels>,
    client_logger: slog::Logger,
}

impl ConnectionSequenceFuture {
    pub fn new(
        client: TcpStream,
        tls_proxy_pubkey: Vec<u8>,
        tls_acceptor: TlsAcceptor,
        identities_proxy: IdentitiesProxy,
        client_logger: slog::Logger,
    ) -> Self {
        Self {
            state: ConnectionSequenceFutureState::NegotiationWithClient(Box::new(SequenceFuture::with_get_state(
                NegotiationWithClientFuture::new(),
                client_logger.clone(),
                GetStateArgs {
                    client: Some(NegotiationWithClientTransport::default().framed(client)),
                    server: None,
                },
            ))),
            client_tls: None,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            tls_acceptor: Some(tls_acceptor),
            identities_proxy: Some(identities_proxy),
            request: None,
            rdp_identity: None,
            filter_config: None,
            joined_static_channels: None,
            client_logger,
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
            self.identities_proxy
                .take()
                .expect("Identities proxy must be set in the constructor"),
            self.tls_acceptor
                .take()
                .expect("TLS acceptor must be set in the constructor"),
            self.client_logger.clone(),
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

        let target_credentials = self.rdp_identity
            .as_ref()
            .expect("The RDP identity must be set after the client negotiation and be taken by reference in the connect server state")
            .target.clone();
        let pdu = create_negotiation_request(
            target_credentials,
            self.request
                .as_ref()
                .expect("For server negotiation future, the request must be set after negotiation with client")
                .clone(),
        )?;

        Ok(SequenceFuture::with_send_state(
            NegotiationWithServerFuture::new(),
            self.client_logger.clone(),
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
        NlaWithServerFuture::new(
            server,
            self.request.as_ref().expect("for NLA server future, the request must be set after negotiation with client").flags,
            server_response_protocol,
            self.rdp_identity
                .as_ref()
                .expect("The RDP identity must be set after the client negotiation and be taken by reference in the server negotiation state").target.clone(),
            true,
            self.client_logger.clone(),
        )
    }
    fn create_mcs_initial_future(
        &mut self,
        server_tls: TlsStream<TcpStream>,
    ) -> SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, DataTransport> {
        let client_tls = self
            .client_tls
            .take()
            .expect("For the McsInitial state, the client TLS stream must be set after the client negotiation");

        SequenceFuture::with_get_state(
            McsInitialFuture::new(FilterConfig::new(
                self.rdp_identity
                    .as_ref()
                    .expect("the RDP identity must be set after the server NLA")
                    .target
                    .clone(),
            )),
            self.client_logger.clone(),
            GetStateArgs {
                client: Some(DataTransport::default().framed(client_tls)),
                server: Some(DataTransport::default().framed(server_tls)),
            },
        )
    }
    fn create_mcs_future(
        &mut self,
        server_tls: TlsStream<TcpStream>,
        static_channels: StaticChannels,
    ) -> SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport> {
        let client_tls = self
            .client_tls
            .take()
            .expect("the client TLS stream must be set after the MCS initial");

        SequenceFuture::with_get_state(
            McsFuture::new(static_channels),
            self.client_logger.clone(),
            GetStateArgs {
                client: Some(McsTransport::default().framed(client_tls)),
                server: Some(McsTransport::default().framed(server_tls)),
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
            self.client_logger.clone(),
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
                        unreachable!("The negotiation with client future must return response");
                    }
                }
                ConnectionSequenceFutureState::NlaWithClient(nla_future) => {
                    let (client_tls, rdp_identity) = try_ready!(nla_future.poll());
                    self.client_tls = Some(client_tls);
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
                        self.state = ConnectionSequenceFutureState::NlaWithServer(Box::new(
                            self.create_nla_server_future(server, protocol)?,
                        ));
                    } else {
                        unreachable!("The negotiation with client future must return response");
                    }
                }
                ConnectionSequenceFutureState::NlaWithServer(nla_future) => {
                    let server_tls = try_ready!(nla_future.poll());

                    self.state =
                        ConnectionSequenceFutureState::McsInitial(Box::new(self.create_mcs_initial_future(server_tls)))
                }
                ConnectionSequenceFutureState::McsInitial(mcs_initial_future) => {
                    let (client_transport, server_transport, filter_config, static_channels) =
                        try_ready!(mcs_initial_future.poll());
                    self.filter_config = Some(filter_config);
                    self.client_tls = Some(client_transport.into_inner());

                    let server_tls = server_transport.into_inner();

                    self.state = ConnectionSequenceFutureState::Mcs(Box::new(
                        self.create_mcs_future(server_tls, static_channels),
                    ));
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
