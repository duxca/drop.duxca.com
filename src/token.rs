//! ドロップのトークン（capability）。
//!
//! CSPRNG（OS の乱数源）で 128bit を作り、base64url（パディングなし）の 22 字で表す。
//! 安全の本体はコードの秘密ではなくこの値の推測不能さ。
//! うっかりログに出さないよう `Debug` / `Display` は実装しない。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::SysRng;
use rand::TryRng;

pub const TOKEN_LEN: usize = 22;
const TOKEN_BYTES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token([u8; TOKEN_BYTES]);

impl Token {
    pub fn generate() -> Result<Self, rand::rngs::SysError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        SysRng.try_fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// 22 字の正規形（base64url・パディングなし・末尾の余りビットが 0）だけを受け付ける。
    /// 正規形に限るので、文字列とトークンは 1 対 1 に対応する。
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != TOKEN_LEN {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
        bytes.try_into().ok().map(Self)
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_tokens_are_22_url_safe_chars_and_round_trip() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let token = Token::generate().unwrap();
            let s = token.encode();
            assert_eq!(s.len(), TOKEN_LEN);
            assert!(s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            assert!(Token::parse(&s) == Some(token));
            assert!(seen.insert(s));
        }
    }

    #[test]
    fn rejects_malformed_tokens() {
        let good = Token::generate().unwrap().encode();
        assert!(Token::parse(&good).is_some());
        for bad in [
            "",
            &good[..21],
            &format!("{good}A"),
            &format!("{}=", &good[..21]),
            // base64 標準アルファベット（+ と /）は不可
            "AAAAAAAAAAAAAAAAAAAA+A",
            "AAAAAAAAAAAAAAAAAAAA/A",
            "AAAAAAAAAAAAAAAAAAAA.A",
            "%41AAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(Token::parse(bad).is_none(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // 128bit = 21 字 * 6bit + 2bit。最終字の下位 4bit が 0 でないものは非正規形。
        assert!(Token::parse("AAAAAAAAAAAAAAAAAAAAAA").is_some());
        assert!(Token::parse("AAAAAAAAAAAAAAAAAAAAAQ").is_some());
        assert!(Token::parse("AAAAAAAAAAAAAAAAAAAAAB").is_none());
        assert!(Token::parse("AAAAAAAAAAAAAAAAAAAAA_").is_none());
    }
}
