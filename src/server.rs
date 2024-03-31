use core::fmt;
use std::{error::Error, net::UdpSocket};

use neon::types::JsError;
use quiche::ConnectionId;

pub trait QUICServer {
    fn listen(&self /* TODO: Add parameters */);
}

pub struct QUICServerImpl {}

#[derive(Debug)]
struct CustomError {
    message: String
}

impl CustomError {
    pub fn new(message: &str) -> CustomError {
        CustomError { message: message.to_owned() }
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
        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| CustomError::new(&e.to_string()))?;

        let _ = config.set_application_protos(&[b"quic-n-dirty"]);

        config
            .load_priv_key_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.key")
            .map_err(|e| CustomError::new(&e.to_string()))?;
        config
            .load_cert_chain_from_pem_file("/Users/rafaelcosta/Developer/quic-n-dirty/cert.crt")
            .map_err(|e| CustomError::new(&e.to_string()))?;

        let socket = UdpSocket::bind("localhost:34254").map_err(|e| CustomError::new(&e.to_string()))?;

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        let mut buf = [0; 2048];

        let (amt, src) = socket.recv_from(&mut buf).map_err(|e| CustomError::new(&e.to_string()))?;

        let mut key: [u8; 32] = rand::random(); // up to 32 elements

        let local_addr = socket.local_addr().unwrap();

        // Server connection.
        let scid: ConnectionId = ConnectionId::from_ref(&key);
        let mut conn = quiche::accept(&scid, None, local_addr, src, &mut config)
            .map_err(|e| CustomError::new(&e.to_string()))?;

        loop {
            let (read, from) = socket.recv_from(&mut buf).unwrap();

            let recv_info = quiche::RecvInfo {
                from,
                to: local_addr,
            };

            let read = match conn.recv(&mut buf[..read], recv_info) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    // Done reading.
                    println!("Done reading!");
                    0 as usize
                }

                Err(e) => {
                    // An error occurred, handle it.
                    println!("Error reading: {}", e.to_string());
                    0 as usize
                }
            };

            println!("Done! Read: {}", read);
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
