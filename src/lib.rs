use std::net::UdpSocket;

use neon::prelude::*;
use quiche::ConnectionId;

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello node"))
}

fn listen(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;

    let _ = config.set_application_protos(&[b"quic-n-dirty"]);

    config
        .load_priv_key_from_pem_file("./key.pem")
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;
    config
        .load_cert_chain_from_pem_file("./cert.pem")
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;

    let socket = UdpSocket::bind("localhost:34254")
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;

    // Receives a single datagram message on the socket. If `buf` is too small to hold
    // the message, it will be cut off.
    let mut buf = [0; 2048];

    let (amt, src) = socket
        .recv_from(&mut buf)
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;

    let mut key: [u8; 32] = rand::random(); // up to 32 elements

    let local_addr = socket.local_addr().unwrap();

    // Server connection.
    let scid: ConnectionId = ConnectionId::from_ref(&key);
    let mut conn = quiche::accept(&scid, None, local_addr, src, &mut config)
        .map_err(|e| JsError::error(&mut cx, e.to_string()).unwrap_err())?;

    loop {
        let (read, from) = socket.recv_from(&mut buf).unwrap();

        let recv_info = quiche::RecvInfo { from, to: local_addr };

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

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("listen", listen)?;
    cx.export_function("hello", hello)?;
    Ok(())
}
