mod server;

use std::net::UdpSocket;
use neon::prelude::*;
use quiche::ConnectionId;
use server::QUICServerImpl;
use server::QUICServer;

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello node"))
}

fn listen(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let server = QUICServerImpl {};
    let thread = std::thread::spawn(move || {
        server.listen();
    });

    let _ = thread.join();

    return Ok(cx.boolean(true));
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("listen", listen)?;
    cx.export_function("hello", hello)?;
    Ok(())
}
