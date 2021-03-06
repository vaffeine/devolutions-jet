use std::io;

use ironrdp::nego::{FailureCode, NegoData, Request, Response, ResponseData, ResponseFlags, SecurityProtocol};
use slog_scope::{debug, info};
use tokio::codec::Framed;
use tokio_tcp::TcpStream;

use super::{FutureState, NextStream, SequenceFutureProperties};
use crate::transport::x224::{NegotiationWithClientTransport, NegotiationWithServerTransport};

pub struct NegotiationWithClientFuture {
    request: Option<Request>,
    response: Option<Response>,
}

impl NegotiationWithClientFuture {
    pub fn new() -> Self {
        Self {
            request: None,
            response: None,
        }
    }
}

impl SequenceFutureProperties<TcpStream, NegotiationWithClientTransport> for NegotiationWithClientFuture {
    type Item = (Framed<TcpStream, NegotiationWithClientTransport>, Request, Response);

    fn process_pdu(&mut self, request: Request) -> io::Result<Option<Response>> {
        let (routing_token, cookie) = match &request.nego_data {
            Some(NegoData::RoutingToken(routing_token)) => (Some(routing_token), None),
            Some(NegoData::Cookie(cookie)) => (None, Some(cookie)),
            None => (None, None),
        };
        info!(
            "Processing negotiation request from the client (routing_token: {:?}, cookie: {:?}, protocol: {:?}, flags: {:?})",
            routing_token, cookie, request.protocol, request.flags,
        );

        let response_data = if request.protocol.contains(SecurityProtocol::HYBRID)
            || request.protocol.contains(SecurityProtocol::HYBRID_EX)
        {
            let protocol = if request.protocol.contains(SecurityProtocol::HYBRID_EX) {
                SecurityProtocol::HYBRID_EX
            } else {
                SecurityProtocol::HYBRID
            };
            let flags = ResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED
                | ResponseFlags::RDP_NEG_RSP_RESERVED
                | ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED
                | ResponseFlags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED;

            ResponseData::Response { flags, protocol }
        } else {
            ResponseData::Failure {
                code: FailureCode::HybridRequiredByServer,
            }
        };

        let response = Response {
            response: Some(response_data),
            dst_ref: 0,
            src_ref: request.src_ref,
        };
        debug!(
            "Sending response to the client: {:?}",
            response.response.as_ref().unwrap()
        );

        self.request = Some(request);
        self.response = Some(response.clone());

        Ok(Some(response))
    }
    fn return_item(
        &mut self,
        mut client: Option<Framed<TcpStream, NegotiationWithClientTransport>>,
        _server: Option<Framed<TcpStream, NegotiationWithClientTransport>>,
    ) -> Self::Item {
        info!("Successfully negotiated with the client");

        (
            client
                .take()
                .expect("After negotiation with client, the client's stream must exist in a return_item method"),
            self.request
                .take()
                .expect("After negotiation with client, request must be set in the process_pdu method"),
            self.response
                .take()
                .expect("After negotiation with client, response must be set in the process_pdu method"),
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Client
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Client
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage
    }
}

pub struct NegotiationWithServerFuture {
    response: Option<Response>,
}

impl NegotiationWithServerFuture {
    pub fn new() -> Self {
        Self { response: None }
    }
}

impl SequenceFutureProperties<TcpStream, NegotiationWithServerTransport> for NegotiationWithServerFuture {
    type Item = (Framed<TcpStream, NegotiationWithServerTransport>, Response);

    fn process_pdu(&mut self, response: Response) -> io::Result<Option<Request>> {
        match response.response {
            Some(ResponseData::Response { protocol, flags }) => {
                info!(
                    "Received negotiation response from the server (protocol: {:?}, flags: {:?})",
                    protocol, flags,
                );

                match protocol {
                    SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX => {
                        self.response = Some(response);

                        Ok(None)
                    }
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Got unsupported security protocol: {:?}", protocol),
                    )),
                }
            }
            Some(ResponseData::Failure { code }) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Received negotiation failure from server (code: {:?})", code),
            )),
            None => Err(io::Error::new(io::ErrorKind::Other, "Received empty response")),
        }
    }
    fn return_item(
        &mut self,
        _client: Option<Framed<TcpStream, NegotiationWithServerTransport>>,
        mut server: Option<Framed<TcpStream, NegotiationWithServerTransport>>,
    ) -> Self::Item {
        info!("Successfully negotiated with the server");

        (
            server
                .take()
                .expect("After negotiation with server, the server's stream must exist in a return_item method"),
            self.response
                .take()
                .expect("After negotiation with server, the response must exist in a return_item method"),
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Server
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Server
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::ParseMessage
    }
}

pub fn create_negotiation_request(username: String, mut request: Request) -> io::Result<Request> {
    request.nego_data = Some(NegoData::Cookie(username));

    Ok(request)
}
