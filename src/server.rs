use core::fmt;
use std::{
    collections::HashMap,
    error::Error,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use mio::net::UdpSocket;
use neon::types::JsError;
use quiche::ConnectionId;
use ring::rand::{SecureRandom, SystemRandom};

const MAX_BUF_SIZE: usize = 65507;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub type ClientId = u64;

pub struct Client {
    pub conn: quiche::Connection,
    pub client_id: ClientId,
    pub app_proto_selected: bool,
    pub max_datagram_size: usize,
    pub loss_rate: f64,
    pub max_send_burst: usize,
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
        let mut pacing = false;

        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        let socket_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 34254);

        let mut socket = UdpSocket::bind(SocketAddr::V4(socket_addr))
            .map_err(|e| CustomError::new(&e.to_string()))?;

        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| CustomError::new(&e.to_string()))?;

        let conn_args = CommonArgs::default();

        config
            .load_priv_key_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.key")
            .map_err(|e| CustomError::new(&e.to_string()))?;
        config
            .load_cert_chain_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.crt")
            .map_err(|e| CustomError::new(&e.to_string()))?;
            
        let _ = config.set_application_protos(&[b"qnd"]);

        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(false);
        config.enable_early_data();
        config.enable_pacing(pacing);

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut next_client_id = 0;
        let mut clients_ids = ClientIdMap::new();
        let mut clients = ClientMap::new();

        let mut continue_write = false;

        let local_addr = socket.local_addr().unwrap();

        loop {
            let timeout = match continue_write {
                true => Some(std::time::Duration::from_secs(0)),
                false => clients.values().filter_map(|c| c.conn.timeout()).min(),
            };

            poll.poll(&mut events, timeout).unwrap();

            'read: loop {
                if events.is_empty() && !continue_write {
                    // Timeout
                    println!("Timeout!!!");
                    clients.values_mut().for_each(|c| c.conn.on_timeout());

                    break 'read;
                }

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    }
                };

                println!("Got {} bytes", len);

                let pkt_buf = &mut buf[..len];

                let header = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,

                    Err(e) => {
                        println!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    }
                };

                println!("Got QUIC packet {:?}; Type: {:#?}", header, header.ty);

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

                        let len = quiche::negotiate_version(&header.scid, &header.dcid, &mut out)
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

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);

                    let mut odcid = None;

                    let attempt_retry = true;

                    if attempt_retry {
                        // attempt retry
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

                            println!("Sent retry packet");
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
                        quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                    let client_id = next_client_id;

                    let client = Client {
                        conn,
                        client_id,
                        app_proto_selected: false,
                        max_datagram_size: MAX_DATAGRAM_SIZE,
                        loss_rate: 0.0,
                        max_send_burst: MAX_BUF_SIZE,
                    };

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

                let recv_info = quiche::RecvInfo { to: local_addr, from };

                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        println!(
                            "{} client.conn.recv failed: {:?}",
                            client.conn.trace_id(),
                            e
                        );
                        continue 'read;
                    }
                };

                println!("{} processed {} bytes", client.conn.trace_id(), read);

                if !client.app_proto_selected
                    && (client.conn.is_in_early_data() || client.conn.is_established())
                {
                    println!("Client Protocol count: {}", client.conn.application_proto().len());
                    client.max_datagram_size = client.conn.max_send_udp_payload_size();
                }

                self.handle_path_events(client);

                // See whether source Connection IDs have been retired.
                while let Some(retired_scid) = client.conn.retired_scid_next() {
                    println!("Retiring source CID {:?}", retired_scid);
                    clients_ids.remove(&retired_scid);
                }

                // Provides as many CIDs as possible.
                while client.conn.scids_left() > 0 {
                    let (scid, reset_token) = Self::generate_cid_and_reset_token(&rng);
                    if client.conn.new_scid(&scid, reset_token, false).is_err() {
                        break;
                    }

                    clients_ids.insert(scid, client.client_id);
                }
            } // 'read

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            continue_write = false;
            for client in clients.values_mut() {
                // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
                let loss_rate = client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
                if loss_rate > client.loss_rate + 0.001 {
                    client.max_send_burst = client.max_send_burst / 4 * 3;
                    // Minimun bound of 10xMSS.
                    client.max_send_burst =
                        client.max_send_burst.max(client.max_datagram_size * 10);
                    client.loss_rate = loss_rate;
                }

                let max_send_burst = client.conn.send_quantum().min(client.max_send_burst)
                    / MAX_DATAGRAM_SIZE
                    * MAX_DATAGRAM_SIZE;
                let mut total_write = 0;
                let mut dst_info = None;

                while total_write < max_send_burst {
                    let (write, send_info) =
                        match client.conn.send(&mut out[total_write..max_send_burst]) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => {
                                println!("{} done writing", client.conn.trace_id());
                                break;
                            }

                            Err(e) => {
                                println!("{} send failed: {:?}", client.conn.trace_id(), e);

                                client.conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        };

                    total_write += write;

                    // Use the first packet time to send, not the last.
                    let _ = dst_info.get_or_insert(send_info);

                    if write < MAX_DATAGRAM_SIZE {
                        continue_write = true;
                        break;
                    }
                }

                if total_write == 0 || dst_info.is_none() {
                    break;
                }

                if let Err(e) = &socket.send_to(&out[..total_write], dst_info.unwrap().from) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("send() would block");
                        break;
                    }

                    panic!("send_to() failed: {:?}", e);
                }

                println!("{} written {} bytes", client.conn.trace_id(), total_write);

                if total_write >= max_send_burst {
                    println!("{} pause writing", client.conn.trace_id(),);
                    continue_write = true;
                    break;
                }
            }

            // Garbage collect closed connections.
            clients.retain(|_, ref mut c| {
                println!("Collecting garbage");

                if c.conn.is_closed() {
                    println!(
                        "{} connection collected {:?} {:?}",
                        c.conn.trace_id(),
                        c.conn.stats(),
                        c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                    );

                    for id in c.conn.source_ids() {
                        let id_owned = id.clone().into_owned();
                        clients_ids.remove(&id_owned);
                    }
                }

                !c.conn.is_closed()
            });
        } // main loop
    }

    /// Generate a stateless retry token.
    ///
    /// The token includes the static string `"quiche"` followed by the IP address
    /// of the client and by the original destination connection ID generated by the
    /// client.
    ///
    /// Note that this function is only an example and doesn't do any cryptographic
    /// authenticate of the token. *It should not be used in production system*.
    fn mint_token(&self, hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
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
        src: &SocketAddr,
        token: &'a [u8],
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
                }

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) is now validated",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) failed validation",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }

                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    println!(
                        "{} Path ({}, {}) is now closed and unusable",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }

                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    println!(
                        "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                        client.conn.trace_id(),
                        cid_seq,
                        old,
                        new
                    );
                }

                quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    println!(
                        "{} Connection migrated to ({}, {})",
                        client.conn.trace_id(),
                        local_addr,
                        peer_addr
                    );
                }
            }
        }
    }

    /// Generate a new pair of Source Connection ID and reset token.
    pub fn generate_cid_and_reset_token<T: SecureRandom>(
        rng: &T,
    ) -> (quiche::ConnectionId<'static>, u128) {
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut scid).unwrap();
        let scid = scid.to_vec().into();
        let mut reset_token = [0; 16];
        rng.fill(&mut reset_token).unwrap();
        let reset_token = u128::from_be_bytes(reset_token);
        (scid, reset_token)
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
