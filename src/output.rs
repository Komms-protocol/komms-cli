use protocol::{ParsedKommsEvent, validate_ref};
use serde_json::{Value, json};

fn hex32(b: &[u8; 32]) -> String {
    faster_hex::hex_string(b.as_slice())
}

fn hex_opt(b: &Option<[u8; 32]>) -> Option<String> {
    b.as_ref().map(hex32)
}

fn hex_vec(b: &Option<Vec<u8>>) -> Option<String> {
    b.as_ref().map(|v| faster_hex::hex_string(v))
}

pub fn ref_json(ref_bytes: &[u8]) -> Value {
    if ref_bytes.is_empty() {
        return json!({ "error": "empty ref" });
    }
    match ref_bytes[0] {
        0x01 => {
            let body = &ref_bytes[1..];
            let s = std::str::from_utf8(body).unwrap_or("<invalid utf-8>");
            json!({ "ref_type": "cid", "ref_type_byte": 1, "cid": s })
        }
        0x02 => {
            if ref_bytes.len() == 33 {
                let h: [u8; 32] = ref_bytes[1..].try_into().unwrap();
                json!({ "ref_type": "content_hash", "ref_type_byte": 2, "sha256": hex32(&h) })
            } else {
                json!({ "ref_type": "content_hash", "error": "expected 33 bytes" })
            }
        }
        b => json!({ "ref_type": "unknown", "ref_type_byte": b }),
    }
}

pub fn event_to_json(ev: &ParsedKommsEvent) -> Value {
    let ref_parsed = ev.ref_bytes.as_deref().map(ref_json);
    json!({
        "v": ev.v,
        "t": ev.t as u8,
        "event_type": format!("{:?}", ev.t),
        "sid": hex_opt(&ev.sid),
        "cid": hex_opt(&ev.cid),
        "did": hex_opt(&ev.did),
        "pid": hex_opt(&ev.pid),
        "mid": hex_opt(&ev.mid),
        "ref": hex_vec(&ev.ref_bytes),
        "ref_decoded": ref_parsed,
        "ref_valid": ev.ref_bytes.as_ref().map(|r| validate_ref(r).is_ok()),
        "enc": ev.enc,
        "ts": ev.ts,
        "n": ev.n,
        "sig": ev.sig.map(|s| faster_hex::hex_string(&s)),
    })
}
