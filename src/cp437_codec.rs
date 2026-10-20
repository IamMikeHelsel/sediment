use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePage {
    Cp437,
    Cp850,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePageError {
    Unmappable,
}

const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
const CP850_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´\u{ad}±‗¾¶§÷¸°¨·¹³²■\u{a0}";

fn build_table(cp: CodePage) -> [char; 256] {
    let mut table: [char; 256] = ['\0'; 256];
    for i in 0u8..=0x7F {
        table[i as usize] = char::from(i);
    }
    let high = match cp {
        CodePage::Cp437 => CP437_HIGH,
        CodePage::Cp850 => CP850_HIGH,
    };
    let chars: Vec<char> = high.chars().collect();
    debug_assert_eq!(chars.len(), 128);
    for i in 0..128 {
        table[0x80 + i] = chars[i];
    }
    table
}

fn build_reverse(cp: CodePage) -> HashMap<char, u8> {
    let table = build_table(cp);
    let mut map = HashMap::with_capacity(256);
    for (code, ch) in table.iter().enumerate() {
        map.insert(*ch, code as u8);
    }
    map
}

static DECODE_CP437: OnceLock<[char; 256]> = OnceLock::new();
static DECODE_CP850: OnceLock<[char; 256]> = OnceLock::new();
static ENCODE_CP437: OnceLock<HashMap<char, u8>> = OnceLock::new();
static ENCODE_CP850: OnceLock<HashMap<char, u8>> = OnceLock::new();

fn decode_table(cp: CodePage) -> &'static [char; 256] {
    match cp {
        CodePage::Cp437 => DECODE_CP437.get_or_init(|| build_table(CodePage::Cp437)),
        CodePage::Cp850 => DECODE_CP850.get_or_init(|| build_table(CodePage::Cp850)),
    }
}

fn encode_table(cp: CodePage) -> &'static HashMap<char, u8> {
    match cp {
        CodePage::Cp437 => ENCODE_CP437.get_or_init(|| build_reverse(CodePage::Cp437)),
        CodePage::Cp850 => ENCODE_CP850.get_or_init(|| build_reverse(CodePage::Cp850)),
    }
}

pub fn decode(bytes: &[u8], cp: CodePage) -> String {
    let table = decode_table(cp);
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        out.push(table[b as usize]);
    }
    out
}

pub fn encode(text: &str, cp: CodePage) -> Result<Vec<u8>, CodePageError> {
    let table = encode_table(cp);
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        match table.get(&ch) {
            Some(&b) => out.push(b),
            None => return Err(CodePageError::Unmappable),
        }
    }
    Ok(out)
}

pub fn decode_zip_name(raw: &[u8], flags: u16) -> String {
    // Flag bit 11 (0x0800) means UTF-8
    if flags & 0x0800 != 0 {
        if let Ok(s) = std::str::from_utf8(raw) {
            return s.to_string();
        }
    }
    // Fallback: CP437
    decode(raw, CodePage::Cp437)
}
