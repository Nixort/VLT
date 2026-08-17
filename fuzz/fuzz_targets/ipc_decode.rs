// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use vlt1_protocol::{read_frame, Request};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = read_frame::<Request, _>(&mut cursor);
});
