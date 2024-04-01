use core::fmt;
use std::{collections::HashMap, error::Error, net::{self, SocketAddr, UdpSocket}};

use neon::types::JsError;
use quiche::ConnectionId;
use ring::rand::SystemRandom;

const MAX_BUF_SIZE: usize = 65507;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub type ClientId = u64;

pub struct Client {
    pub conn: quiche::Connection,
    pub client_id: ClientId,
}

pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap = HashMap<ClientId, Client>;

pub trait QUICServer {
    fn listen(&self /* TODO: Add parameters */);
}

pub struct QUICServerImpl {}

#[derive(Debug)]
struct CustomError {
    message: String,
}

impl CustomError {
    pub fn new(message: &str) -> CustomError {
        CustomError {
            message: message.to_owned(),
        }
    }
}

pub struct CommonArgs {
    pub max_data: u64,
    pub max_window: u64,
    pub max_stream_data: u64,
    pub max_stream_window: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub idle_timeout: u64,
    pub early_data: bool,
    pub dump_packet_path: Option<String>,
    pub no_grease: bool,
    pub cc_algorithm: String,
    pub disable_hystart: bool,
    pub dgrams_enabled: bool,
    pub dgram_count: u64,
    pub dgram_data: String,
    pub max_active_cids: u64,
    pub enable_active_migration: bool,
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub initial_cwnd_packets: u64,
}

impl CommonArgs {
    fn default() -> Self {
        CommonArgs {
            max_data: 10000000,
            max_window: 25165824,
            max_stream_data: 1000000,
            max_stream_window: 16777216,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            idle_timeout: 30000,
            early_data: false,
            dump_packet_path: None,
            no_grease: false,
            cc_algorithm: "cubic".to_string(),
            disable_hystart: false,
            dgrams_enabled: false,
            dgram_count: 0,
            dgram_data: "quack".to_string(),
            max_active_cids: 2,
            enable_active_migration: false,
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            initial_cwnd_packets: 10,
        }
    }
}

impl Error for CustomError {}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}

impl QUICServerImpl {
    fn _listen(&self) -> Result<(), CustomError> {
        let mut buf = [0; MAX_BUF_SIZE];
        let mut out = [0; MAX_BUF_SIZE];

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| CustomError::new(&e.to_string()))?;

        let conn_args = CommonArgs::default();

        config
            .load_priv_key_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.key")
            .map_err(|e| CustomError::new(&e.to_string()))?;
        config
            .load_cert_chain_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.crt")
            .map_err(|e| CustomError::new(&e.to_string()))?;

        let _ = config.set_application_protos(&[b"qnd", b"http/0.9"]);

        // config.discover_pmtu(true);
        config.set_max_idle_timeout(conn_args.idle_timeout);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(conn_args.max_data);
        config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
        config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
        config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
        config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
        config.set_initial_max_streams_uni(conn_args.max_streams_uni);
        config.set_disable_active_migration(!conn_args.enable_active_migration);
        config.set_active_connection_id_limit(conn_args.max_active_cids);
        config.set_initial_congestion_window_packets(
            usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
        );
    
        config.set_max_connection_window(conn_args.max_window);
        config.set_max_stream_window(conn_args.max_stream_window);
    
        config.enable_pacing(true);
    

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut next_client_id = 0;
        let mut clients_ids = ClientIdMap::new();
        let mut clients = ClientMap::new();

        let socket =
            UdpSocket::bind("127.0.0.1:34254").map_err(|e| CustomError::new(&e.to_string()))?;

        let local_addr = socket.local_addr().unwrap();

        'read: loop {            
            let (read, from) = match socket.recv_from(&mut buf) {

                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            println!("UDP read: {}", read);

            let pkt_buf = &mut buf[..read];

            // Parse the QUIC packet's header.
            let header = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    println!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            println!("Got QUIC packet {:?}", header);

            let conn_id = ring::hmac::sign(&conn_id_seed, &header.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id: ConnectionId<'static> = conn_id.to_vec().into();

            println!("Connection ID: {:x?}", conn_id);

            let client = if !clients_ids.contains_key(&header.dcid)
                && !clients_ids.contains_key(&conn_id)
            {
                if header.ty != quiche::Type::Initial {
                    println!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(header.version) {
                    println!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&header.scid, &header.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if true {
                    // Token is always present in Initial packets.
                    let token = header.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        println!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = self.mint_token(&header, &from);

                        let len = quiche::retry(
                            &header.scid,
                            &header.dcid,
                            &scid,
                            &new_token,
                            header.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                println!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = self.validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        println!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != header.dcid.len() {
                        println!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&header.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                println!("New connection: dcid={:?} scid={:?}", header.dcid, scid);

                #[allow(unused_mut)]
                let mut conn =
                    quiche::accept(&scid, None, local_addr, from, &mut config).unwrap();

                let client_id = next_client_id;

                let client = Client { conn, client_id };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;

                clients.get_mut(&client_id).unwrap()
            } else {
                // Previous connection(?)
                let cid = match clients_ids.get(&header.dcid) {
                    Some(v) => v,
                    None => clients_ids.get(&conn_id).unwrap(),
                };

                let found = clients.get_mut(cid).unwrap();
                println!("Previous client: {:?}", header.dcid);
                found
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            println!("Reading from connection...");

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => {
                    println!("Coalesced: {}", v);
                    v
                },

                Err(e) => {
                    println!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue;
                },
            };

            println!("{} processed {} bytes", client.conn.trace_id(), read);

            println!("Negotiated protocol amount: {:?}", client.conn.application_proto().len());

            println!("Is in early data: {}", client.conn.is_in_early_data());
            println!("Is established: {}", client.conn.is_established());

            self.handle_path_events(client);

            // let mut bytes = b"Hello from Node via Rust!".to_owned();
            // let res = client.conn.send(&mut bytes);

            // let mut written = 0;
            // let mut dst_info = None;

            // match res {
            //     Ok(bytes_written) => {
            //         println!("Wrote sending message: {}", bytes_written.0);
            //         written = bytes_written.0;
            //         let _ = dst_info.get_or_insert(bytes_written.1);
            //     },
            //     Err(e) => println!("Error sending message: {}", e.to_string()),
            // }

            // match socket.send_to(&out[..written], dst_info.unwrap().to) {
            //     Err(e) => println!("Error writing to socket {}", e.to_string()),
            //     Ok(a) => println!("Written {} to socket", a),
            // }

            // if let Err(e) = send_to(
            //     &socket,
            //     &out[..total_write],
            //     &dst_info.unwrap(),
            //     client.max_datagram_size,
            //     pacing,
            //     enable_gso,
            // ) {
            //     if e.kind() == std::io::ErrorKind::WouldBlock {
            //         trace!("send() would block");
            //         break;
            //     }

            //     panic!("send_to() failed: {:?}", e);
            // }

            // trace!("{} written {} bytes", client.conn.trace_id(), total_write);

            if client.conn.is_established() {
                for stream_id in client.conn.readable() {
                    // Stream is readable, read until there's no more data.
                    while let Ok((read, fin)) = client.conn.stream_recv(stream_id, &mut buf) {
                        println!("Got {} bytes on stream {}", read, stream_id);
                    }
                }
            }
        }

        Ok(())
    }

    /// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(&self, hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    &self,
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

    fn handle_path_events(&self, client: &mut Client) {
        while let Some(qe) = client.conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(local_addr, peer_addr) => {
                    println!(
                        "{} Seen new path ({}, {})",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
    
                    // Directly probe the new path.
                    client
                        .conn
                        .probe_path(local_addr, peer_addr)
                        .expect("cannot probe");
                },
    
                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) is now validated",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) failed validation",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) is now closed and unusable",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
    
                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    println!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        client.conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                },
    
                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    println!(
                        "{} Connection migrated to ({}, {})",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                },
            }
        }
    }
}

impl QUICServer for QUICServerImpl {
    fn listen(&self /* TODO: Add parameters */) {
        match self._listen() {
            Err(e) => {
                println!("Listen returned error: {}", e.message)
            }

            Ok(()) => {
                println!("Listen success")
            }
        }
    }
}
