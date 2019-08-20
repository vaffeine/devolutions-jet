use futures::{Async, AsyncSink, Future, Sink, Stream};
use log::{debug, error};
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;
use url::Url;

use crate::interceptor::PacketInterceptor;
use crate::transport::{JetFuture, JetSink, JetSinkType, JetStream, JetStreamType, Transport};
use crate::utils::url_to_socket_arr;

trait StreamWrapper: AsyncRead + AsyncWrite + Read + Write {
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
    fn shutdown(&self) -> std::io::Result<()>;
    fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error>;
}

struct TcpStreamWrapper {
    stream: TcpStream,
}

struct TlsStreamWrapper {
    stream: TlsStream<TcpStream>,
}

impl StreamWrapper for TcpStreamWrapper {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn shutdown(&self) -> std::io::Result<()> {
        TcpStream::shutdown(&self.stream, std::net::Shutdown::Both)
    }

    fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        AsyncWrite::shutdown(&mut self.stream)
    }
}

impl StreamWrapper for TlsStreamWrapper {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.get_ref().get_ref().peer_addr()
    }

    fn shutdown(&self) -> std::io::Result<()> {
        self.stream.get_ref().get_ref().shutdown(std::net::Shutdown::Both)
    }

    fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        AsyncWrite::shutdown(&mut self.stream)
    }
}

impl Read for TcpStreamWrapper {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(&mut buf)
    }
}

impl Read for TlsStreamWrapper {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(&mut buf)
    }
}

impl Write for TcpStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(&buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Write for TlsStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(&buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl AsyncRead for TcpStreamWrapper {}

impl AsyncRead for TlsStreamWrapper {}

impl AsyncWrite for TcpStreamWrapper {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        AsyncWrite::shutdown(&mut self.stream)
    }
}

impl AsyncWrite for TlsStreamWrapper {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        AsyncWrite::shutdown(&mut self.stream)
    }
}

pub struct TcpTransport {
    stream: Arc<Mutex<dyn StreamWrapper + Send>>,
}

impl Clone for TcpTransport {
    fn clone(&self) -> Self {
        TcpTransport {
            stream: self.stream.clone(),
        }
    }
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TcpStreamWrapper { stream })),
        }
    }

    pub fn new_tls(stream: TlsStream<TcpStream>) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TlsStreamWrapper { stream })),
        }
    }
}

impl Read for TcpTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.read(&mut buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncRead for TcpTransport {}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.write(&buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.flush(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncWrite for TcpTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.async_shutdown(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl Transport for TcpTransport {
    fn connect(url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        let socket_addr = url_to_socket_arr(&url);
        match url.scheme() {
            "tcp" => Box::new(TcpStream::connect(&socket_addr).map(TcpTransport::new)) as JetFuture<Self>,
            "tls" => {
                let socket = TcpStream::connect(&socket_addr);
                let cx = TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()
                    .unwrap();
                let cx = tokio_tls::TlsConnector::from(cx);

                let url_clone = url.clone();
                let tls_handshake = socket.and_then(move |socket| {
                    cx.connect(url_clone.host_str().unwrap_or(""), socket)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
                let request = tls_handshake.map(TcpTransport::new_tls);
                Box::new(request) as JetFuture<Self>
            }

            scheme => {
                panic!("Unsuported scheme: {}", scheme);
            }
        }
    }

    fn message_sink(&self) -> JetSinkType<Vec<u8>> {
        Box::new(TcpJetSink::new(self.stream.clone()))
    }

    fn message_stream(&self) -> JetStreamType<Vec<u8>> {
        Box::new(TcpJetStream::new(self.stream.clone()))
    }
}

pub const TCP_READ_LEN: usize = 57343;

struct TcpJetStream {
    stream: Arc<Mutex<dyn StreamWrapper + Send>>,
    nb_bytes_read: u64,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
}

impl TcpJetStream {
    fn new(stream: Arc<Mutex<dyn StreamWrapper + Send>>) -> Self {
        TcpJetStream {
            stream,
            nb_bytes_read: 0,
            packet_interceptor: None,
        }
    }
}

impl Stream for TcpJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if let Ok(ref mut stream) = self.stream.try_lock() {
            let mut result = Vec::new();
            while result.len() <= TCP_READ_LEN {
                let mut buffer = [0u8; 8192];
                match stream.poll_read(&mut buffer) {
                    Ok(Async::Ready(0)) => {
                        if !result.is_empty() {
                            if let Some(interceptor) = self.packet_interceptor.as_mut() {
                                let peer_addr = match stream.peer_addr() {
                                    Ok(addr) => Some(addr),
                                    _ => None,
                                };

                                interceptor.on_new_packet(peer_addr, &result);
                            }

                            return Ok(Async::Ready(Some(result)));
                        }

                        return Ok(Async::Ready(None));
                    }

                    Ok(Async::Ready(len)) => {
                        self.nb_bytes_read += len as u64;
                        debug!("{} bytes read on {}", len, stream.peer_addr().unwrap());
                        if len < buffer.len() {
                            result.extend_from_slice(&buffer[0..len]);
                        } else {
                            result.extend_from_slice(&buffer);
                            continue;
                        }

                        if let Some(interceptor) = self.packet_interceptor.as_mut() {
                            let peer_addr = match stream.peer_addr() {
                                Ok(addr) => Some(addr),
                                _ => None,
                            };

                            interceptor.on_new_packet(peer_addr, &result);
                        }

                        return Ok(Async::Ready(Some(result)));
                    }

                    Ok(Async::NotReady) => {
                        if !result.is_empty() {
                            if let Some(interceptor) = self.packet_interceptor.as_mut() {
                                let peer_addr = match stream.peer_addr() {
                                    Ok(addr) => Some(addr),
                                    _ => None,
                                };

                                interceptor.on_new_packet(peer_addr, &result);
                            }

                            return Ok(Async::Ready(Some(result)));
                        }

                        return Ok(Async::NotReady);
                    }

                    Err(e) => {
                        error!("Can't read on socket: {}", e);
                        return Ok(Async::Ready(None));
                    }
                }
            }
            Ok(Async::Ready(Some(result)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl JetStream for TcpJetStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        let stream = self.stream.lock().unwrap();

        match stream.peer_addr() {
            Ok(addr) => Some(addr),
            _ => None,
        }
    }

    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct TcpJetSink {
    stream: Arc<Mutex<dyn StreamWrapper + Send>>,
    nb_bytes_written: u64,
}

impl TcpJetSink {
    fn new(stream: Arc<Mutex<dyn StreamWrapper + Send>>) -> Self {
        TcpJetSink {
            stream,
            nb_bytes_written: 0,
        }
    }

    fn _nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }
}

impl Sink for TcpJetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        mut item: <Self as Sink>::SinkItem,
    ) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            debug!("{} bytes to write on {}", item.len(), stream.peer_addr().unwrap());
            match stream.poll_write(&item) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.nb_bytes_written += len as u64;
                        item.drain(0..len);
                        debug!("{} bytes written on {}", len, stream.peer_addr().unwrap())
                    } else {
                        debug!("0 bytes written on {}", stream.peer_addr().unwrap())
                    }

                    if item.is_empty() {
                        Ok(AsyncSink::Ready)
                    } else {
                        futures::task::current().notify();
                        Ok(AsyncSink::NotReady(item))
                    }
                }
                Ok(Async::NotReady) => Ok(AsyncSink::NotReady(item)),
                Err(e) => {
                    error!("Can't write on socket: {}", e);
                    Ok(AsyncSink::Ready)
                }
            }
        } else {
            Ok(AsyncSink::NotReady(item))
        }
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            stream.poll_flush()
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl JetSink for TcpJetSink {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }
}
