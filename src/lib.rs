mod server;

use neon::prelude::*;
use server::QUICServer;
use server::QUICServerImpl;
use std::sync::mpsc::channel;
use std::sync::Arc;

struct Message {
    pub stream_identifier: u32, // 62-bit channel identifier
    pub message: String,
}

fn listen(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let on_new_message = cx.argument::<JsFunction>(0).unwrap().root(&mut cx);
    let on_new_message = Arc::from(on_new_message);

    let send_handle = cx.argument::<JsFunction>(1).unwrap().root(&mut cx);
    let send_handle = Arc::from(send_handle);

    let (tx, rx) = channel::<Message>(); // Output from Socket
    let (tx1, rx1) = channel::<Message>(); // Input into Socket

    let server = QUICServerImpl {};

    let thread = std::thread::spawn(move || {
        server.listen(tx, rx1);
    });

    // Unbounded receiver waiting for all senders to complete.
    while let Ok(msg) = rx.recv() {
        let on_new_message_clone = on_new_message.clone();
        let call = on_new_message_clone.to_inner(&mut cx);
        let this = cx.undefined();
        let string: Handle<'_, JsValue> = cx.string(msg.message).as_value(&mut cx);
        let stream_identifier: Handle<'_, JsValue> = cx.number(msg.stream_identifier).as_value(&mut cx);
        let _ = call.call(&mut cx, this, vec![stream_identifier, string]);
    }

    let _ = thread.join();

    return Ok(cx.boolean(true));
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("listen", listen)?;
    Ok(())
}
