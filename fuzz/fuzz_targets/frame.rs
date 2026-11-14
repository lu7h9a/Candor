//! Socket framing and message decoding (both directions): any bytes give a
//! frame, an error or EOF, never a panic or an allocation over the cap.
#![no_main]
use libfuzzer_sys::fuzz_target;
use candor_proto::{
    MAX_CLIENT_FRAME, MAX_DAEMON_FRAME, decode_client, decode_daemon, read_frame,
};

fuzz_target!(|data: &[u8]| {
    for max in [MAX_CLIENT_FRAME, MAX_DAEMON_FRAME] {
        let mut r = data;
        while let Ok(Some(body)) = read_frame(&mut r, max) {
            assert!(body.len() <= max as usize);
            let _ = decode_client(&body);
            let _ = decode_daemon(&body);
        }
    }
    let _ = decode_client(data);
    let _ = decode_daemon(data);
});
