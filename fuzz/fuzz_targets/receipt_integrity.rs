#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = cmdtrail::receipt::parse_receipt_document(data) {
        let _ = cmdtrail::integrity::verify_receipt(&receipt);
    }
});
