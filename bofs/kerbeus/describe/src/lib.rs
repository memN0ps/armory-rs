//! # Describe BOF
//!
//! Parses and displays detailed information about a base64-encoded .kirbi
//! ticket (KRB-CRED) using a built-in ASN.1 BER decoder. Shows service
//! name, realm, client name, timestamps, flags, and encryption type.
//!
//! ## MITRE ATT&CK
//! - T1558 - Steal or Forge Kerberos Tickets
//!
//! ## Arguments
//! - `/ticket:BASE64` - Base64-encoded .kirbi ticket (required)

#![no_std]

use alloc::string::String;
use alloc::vec::Vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};

const FLAG_FORWARDABLE: u32 = 0x40000000;
const FLAG_FORWARDED: u32 = 0x20000000;
const FLAG_PROXIABLE: u32 = 0x10000000;
const FLAG_PROXY: u32 = 0x08000000;
const FLAG_MAY_POSTDATE: u32 = 0x04000000;
const FLAG_POSTDATED: u32 = 0x02000000;
const FLAG_INVALID: u32 = 0x01000000;
const FLAG_RENEWABLE: u32 = 0x00800000;
const FLAG_INITIAL: u32 = 0x00400000;
const FLAG_PRE_AUTHENT: u32 = 0x00200000;
const FLAG_HW_AUTHENT: u32 = 0x00100000;
const FLAG_OK_AS_DELEGATE: u32 = 0x00040000;
const FLAG_ENC_PA_REP: u32 = 0x00010000;

struct Asn {
    class: u8,
    tag: u32,
    value: Vec<u8>,
    children: Vec<Asn>,
}

fn parse_asn(data: &[u8]) -> Option<Asn> {
    let (elem, _) = parse_one(data, 0)?;
    Some(elem)
}

fn parse_one(data: &[u8], mut pos: usize) -> Option<(Asn, usize)> {
    if pos >= data.len() {
        return None;
    }

    let b = data[pos];
    pos += 1;
    let class = (b >> 6) & 0x03;
    let constructed = (b & 0x20) != 0;
    let mut tag = (b & 0x1F) as u32;

    if tag == 0x1F {
        tag = 0;
        loop {
            if pos >= data.len() {
                return None;
            }
            let b = data[pos];
            pos += 1;
            tag = (tag << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    if pos >= data.len() {
        return None;
    }
    let len_byte = data[pos];
    pos += 1;
    let length = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x80 {
        return None;
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if pos + num_bytes > data.len() {
            return None;
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | data[pos + i] as usize;
        }
        pos += num_bytes;
        l
    };

    if pos + length > data.len() {
        return None;
    }
    let value = data[pos..pos + length].to_vec();

    let children = if constructed {
        parse_children(&value)
    } else {
        Vec::new()
    };

    Some((
        Asn {
            class,
            tag,
            value,
            children,
        },
        pos + length,
    ))
}

fn parse_children(data: &[u8]) -> Vec<Asn> {
    let mut children = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if let Some((child, new_pos)) = parse_one(data, pos) {
            children.push(child);
            pos = new_pos;
        } else {
            break;
        }
    }
    children
}

fn find_ctx(asn: &Asn, tag: u32) -> Option<&Asn> {
    asn.children
        .iter()
        .find(|&child| child.class == 2 && child.tag == tag)
}

fn get_int(asn: &Asn) -> i64 {
    let data = &asn.value;
    if data.is_empty() {
        return 0;
    }
    let mut val = if data[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in data {
        val = (val << 8) | b as i64;
    }
    val
}

fn get_string(asn: &Asn) -> String {
    String::from_utf8_lossy(&asn.value).into_owned()
}

fn get_bit_flags(asn: &Asn) -> u32 {
    if asn.value.len() < 2 {
        return 0;
    }
    let mut flags = 0u32;
    for i in 1..asn.value.len().min(5) {
        flags = (flags << 8) | asn.value[i] as u32;
    }
    flags
}

struct DateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

fn parse_generalized_time(asn: &Asn) -> DateTime {
    let s = &asn.value;
    let d2 = |off: usize| -> u8 {
        if off + 1 >= s.len() {
            return 0;
        }
        (s[off] - b'0') * 10 + (s[off + 1] - b'0')
    };
    let d4 = |off: usize| -> u16 {
        if off + 3 >= s.len() {
            return 0;
        }
        (s[off] - b'0') as u16 * 1000
            + (s[off + 1] - b'0') as u16 * 100
            + (s[off + 2] - b'0') as u16 * 10
            + (s[off + 3] - b'0') as u16
    };
    DateTime {
        year: d4(0),
        month: d2(4),
        day: d2(6),
        hour: d2(8),
        minute: d2(10),
        second: d2(12),
    }
}

struct PrincipalName {
    name_type: i64,
    names: Vec<String>,
}

fn parse_principal_name(asn: &Asn) -> PrincipalName {
    let mut pn = PrincipalName {
        name_type: 0,
        names: Vec::new(),
    };
    if let Some(t) = find_ctx(asn, 0) {
        if let Some(inner) = t.children.first() {
            pn.name_type = get_int(inner);
        }
    }
    if let Some(t) = find_ctx(asn, 1) {
        if let Some(seq) = t.children.first() {
            for child in &seq.children {
                pn.names.push(get_string(child));
            }
        }
    }
    pn
}

fn format_principal(pn: &PrincipalName) -> String {
    if pn.names.len() == 1 {
        pn.names[0].clone()
    } else if pn.names.len() > 1 {
        alloc::format!("{}/{}", pn.names[0], pn.names[1])
    } else {
        String::from("(unknown)")
    }
}

struct KrbCredInfo {
    key_type: i64,
    prealm: String,
    pname: PrincipalName,
    flags: u32,
    starttime: DateTime,
    endtime: DateTime,
    renew_till: DateTime,
    srealm: String,
    sname: PrincipalName,
}

fn parse_krb_cred_info(asn: &Asn) -> KrbCredInfo {
    let mut info = KrbCredInfo {
        key_type: 0,
        prealm: String::new(),
        pname: PrincipalName {
            name_type: 0,
            names: Vec::new(),
        },
        flags: 0,
        starttime: DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        },
        endtime: DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        },
        renew_till: DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        },
        srealm: String::new(),
        sname: PrincipalName {
            name_type: 0,
            names: Vec::new(),
        },
    };

    for child in &asn.children {
        if child.class != 2 {
            continue;
        }
        match child.tag {
            0 => {
                if let Some(key_seq) = child.children.first() {
                    if let Some(kt) = find_ctx(key_seq, 0) {
                        if let Some(inner) = kt.children.first() {
                            info.key_type = get_int(inner);
                        }
                    }
                }
            }
            1 => {
                if let Some(c) = child.children.first() {
                    info.prealm = get_string(c);
                }
            }
            2 => {
                if let Some(c) = child.children.first() {
                    info.pname = parse_principal_name(c);
                }
            }
            3 => {
                if let Some(c) = child.children.first() {
                    info.flags = get_bit_flags(c);
                }
            }
            6 => {
                if let Some(c) = child.children.first() {
                    info.starttime = parse_generalized_time(c);
                }
            }
            7 => {
                if let Some(c) = child.children.first() {
                    info.endtime = parse_generalized_time(c);
                }
            }
            8 => {
                if let Some(c) = child.children.first() {
                    info.renew_till = parse_generalized_time(c);
                }
            }
            9 => {
                if let Some(c) = child.children.first() {
                    info.srealm = get_string(c);
                }
            }
            10 => {
                if let Some(c) = child.children.first() {
                    info.sname = parse_principal_name(c);
                }
            }
            _ => {}
        }
    }
    info
}

fn flags_to_string(flags: u32) -> String {
    let mut s = String::new();
    if flags & FLAG_FORWARDABLE != 0 {
        s.push_str("forwardable ");
    }
    if flags & FLAG_FORWARDED != 0 {
        s.push_str("forwarded ");
    }
    if flags & FLAG_PROXIABLE != 0 {
        s.push_str("proxiable ");
    }
    if flags & FLAG_PROXY != 0 {
        s.push_str("proxy ");
    }
    if flags & FLAG_MAY_POSTDATE != 0 {
        s.push_str("may_postdate ");
    }
    if flags & FLAG_POSTDATED != 0 {
        s.push_str("postdated ");
    }
    if flags & FLAG_INVALID != 0 {
        s.push_str("invalid ");
    }
    if flags & FLAG_RENEWABLE != 0 {
        s.push_str("renewable ");
    }
    if flags & FLAG_INITIAL != 0 {
        s.push_str("initial ");
    }
    if flags & FLAG_PRE_AUTHENT != 0 {
        s.push_str("pre_authent ");
    }
    if flags & FLAG_HW_AUTHENT != 0 {
        s.push_str("hw_authent ");
    }
    if flags & FLAG_OK_AS_DELEGATE != 0 {
        s.push_str("ok_as_delegate ");
    }
    if flags & FLAG_ENC_PA_REP != 0 {
        s.push_str("enc_pa_rep ");
    }
    s
}

fn etype_name(etype: i64) -> &'static str {
    match etype {
        23 => "rc4_hmac",
        17 => "aes128_cts_hmac_sha1",
        18 => "aes256_cts_hmac_sha1",
        _ => "unknown",
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    let mut padding = 0;
    if input.is_empty() {
        return None;
    }
    if input[input.len() - 1] == b'=' {
        padding += 1;
    }
    if input.len() > 1 && input[input.len() - 2] == b'=' {
        padding += 1;
    }
    let out_len = (input.len() * 3) / 4 - padding;
    let mut output = Vec::with_capacity(out_len);
    let mut i = 0;
    while i < input.len() {
        let a = b64v(input[i]);
        i += 1;
        let b = if i < input.len() { b64v(input[i]) } else { 0 };
        i += 1;
        let c = if i < input.len() { b64v(input[i]) } else { 0 };
        i += 1;
        let d = if i < input.len() { b64v(input[i]) } else { 0 };
        i += 1;
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        if output.len() < out_len {
            output.push(((triple >> 16) & 0xFF) as u8);
        }
        if output.len() < out_len {
            output.push(((triple >> 8) & 0xFF) as u8);
        }
        if output.len() < out_len {
            output.push((triple & 0xFF) as u8);
        }
    }
    Some(output)
}

fn b64v(c: u8) -> u32 {
    match c {
        b'A'..=b'Z' => (c - b'A') as u32,
        b'a'..=b'z' => (c - b'a' + 26) as u32,
        b'0'..=b'9' => (c - b'0' + 52) as u32,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    if let Some(pos) = params.find(name) {
        let after = &params[pos + name.len()..];
        let end = after.find(' ').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn describe_ticket(data: &[u8]) {
    let root = match parse_asn(data) {
        Some(r) => r,
        None => {
            eprintln!("[X] Failed to parse ASN.1 structure");
            return;
        }
    };

    let body = if root.class == 1 && root.tag == 22 {
        if let Some(seq) = root.children.first() {
            seq
        } else {
            &root
        }
    } else {
        &root
    };

    let enc_part_ctx = match find_ctx(body, 3) {
        Some(e) => e,
        None => {
            eprintln!("[X] No enc-part found in KRB-CRED");
            return;
        }
    };

    let enc_data_seq = match enc_part_ctx.children.first() {
        Some(s) => s,
        None => {
            eprintln!("[X] Invalid enc-part structure");
            return;
        }
    };

    let cipher_ctx = match find_ctx(enc_data_seq, 2) {
        Some(c) => c,
        None => {
            eprintln!("[X] No cipher in enc-part");
            return;
        }
    };

    let cipher_bytes = match cipher_ctx.children.first() {
        Some(c) => &c.value,
        None => {
            eprintln!("[X] Invalid cipher");
            return;
        }
    };

    let enc_cred_part = match parse_asn(cipher_bytes) {
        Some(r) => r,
        None => {
            eprintln!("[X] Failed to parse EncKrbCredPart");
            return;
        }
    };

    let inner = if enc_cred_part.class == 1 {
        if let Some(seq) = enc_cred_part.children.first() {
            seq
        } else {
            &enc_cred_part
        }
    } else {
        &enc_cred_part
    };

    let ticket_info_ctx = match find_ctx(inner, 0) {
        Some(t) => t,
        None => {
            eprintln!("[X] No ticket-info in EncKrbCredPart");
            return;
        }
    };

    let ticket_info_seq = match ticket_info_ctx.children.first() {
        Some(s) => s,
        None => {
            eprintln!("[X] Invalid ticket-info");
            return;
        }
    };

    let first_info = match ticket_info_seq.children.first() {
        Some(i) => i,
        None => {
            eprintln!("[X] No KrbCredInfo entries");
            return;
        }
    };

    let info = parse_krb_cred_info(first_info);

    println!(
        "  ServiceName              :  {}",
        format_principal(&info.sname)
    );
    println!("  ServiceRealm             :  {}", info.srealm);
    println!(
        "  UserName                 :  {}",
        format_principal(&info.pname)
    );
    println!("  UserRealm                :  {}", info.prealm);
    let st = &info.starttime;
    let et = &info.endtime;
    let rt = &info.renew_till;
    println!(
        "  StartTime (UTC)          :  {:02}/{:02}/{:04} {:02}:{:02}:{:02}",
        st.day, st.month, st.year, st.hour, st.minute, st.second
    );
    println!(
        "  EndTime (UTC)            :  {:02}/{:02}/{:04} {:02}:{:02}:{:02}",
        et.day, et.month, et.year, et.hour, et.minute, et.second
    );
    println!(
        "  RenewTill (UTC)          :  {:02}/{:02}/{:04} {:02}:{:02}:{:02}",
        rt.day, rt.month, rt.year, rt.hour, rt.minute, rt.second
    );
    println!(
        "  Flags                    :  {}",
        flags_to_string(info.flags)
    );
    println!(
        "  KeyType                  :  {}",
        etype_name(info.key_type)
    );
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    println!("[*] Action: Describe ticket\n");

    if len == 0 {
        eprintln!("[X] You must supply a /ticket!");
        return;
    }

    let mut parser = DataParser::new(args, len);
    let params = String::from(parser.get_str());

    let ticket_b64 = match get_param(&params, "/ticket:") {
        Some(t) => t,
        None => {
            eprintln!("[X] You must supply a /ticket!");
            return;
        }
    };

    let ticket_bytes = match base64_decode(ticket_b64) {
        Some(b) if !b.is_empty() => b,
        _ => {
            eprintln!("[X] Failed to decode base64 ticket");
            return;
        }
    };

    describe_ticket(&ticket_bytes);
}
