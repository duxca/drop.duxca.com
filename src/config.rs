//! 環境変数（`DROP_*`）からの設定。`.env` も読む（main で dotenvy）。
//! 設定値はログに出さない。

use crate::store::{Limits, MAX_TEXT_CHARS};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Config {
    /// 公開側（nginx から中継する）。loopback 必須。
    #[serde(default = "default_public_addr")]
    pub public_addr: SocketAddr,
    /// admin 側（nginx から中継しない）。loopback 必須。
    #[serde(default = "default_admin_addr")]
    pub admin_addr: SocketAddr,
    #[serde(default = "default_default_ttl_secs")]
    pub default_ttl_secs: u64,
    #[serde(default = "default_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_max_drops")]
    pub max_drops: usize,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: usize,
    /// 遠隔 admin（公開側 `POST /api/drops`）の検証子。Bearer トークンの
    /// SHA-256 ハッシュ（16 進 64 字）をカンマ区切りで並べる。
    /// 未設定・空なら遠隔 admin は無効（常に 404）。
    #[serde(default)]
    pub remote_admin_token_sha256s: Option<String>,
}

/// 同時に受け付ける検証子の上限（現行＋ローテーションの重ね期間用）。
const MAX_REMOTE_ADMIN_HASHES: usize = 8;

fn default_public_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8470))
}

fn default_admin_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8471))
}

fn default_default_ttl_secs() -> u64 {
    600
}

fn default_max_ttl_secs() -> u64 {
    3600
}

fn default_max_drops() -> usize {
    1000
}

fn default_max_total_bytes() -> usize {
    1024 * 1024
}

/// `DROP_REMOTE_ADMIN_TOKEN_SHA256S` の中身（16 進ハッシュのカンマ区切り）を解釈する。
/// 未設定・空・空白だけなら「無効」を表す空ベクタを返す。
fn parse_remote_admin_hashes(raw: Option<&str>) -> anyhow::Result<Vec<[u8; 32]>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.len() > MAX_REMOTE_ADMIN_HASHES {
        anyhow::bail!(
            "DROP_REMOTE_ADMIN_TOKEN_SHA256S must list at most {MAX_REMOTE_ADMIN_HASHES} hashes"
        );
    }
    let mut hashes = Vec::with_capacity(parts.len());
    for part in parts {
        if part.len() != 64 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!(
                "DROP_REMOTE_ADMIN_TOKEN_SHA256S entries must be SHA-256 hashes in hex (64 chars)"
            );
        }
        let mut hash = [0u8; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&part[2 * i..2 * i + 2], 16).expect("hex checked above");
        }
        hashes.push(hash);
    }
    Ok(hashes)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let config: Self = envy::prefixed("DROP_").from_env()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // nginx 中継後の送信元も loopback になるので、送信元 IP で公開と admin は区別できない。
        // 区別はポートだけで行う。どちらも外から直接届かないよう loopback に限る。
        if !self.public_addr.ip().is_loopback() {
            anyhow::bail!("DROP_PUBLIC_ADDR must be a loopback address");
        }
        if !self.admin_addr.ip().is_loopback() {
            anyhow::bail!("DROP_ADMIN_ADDR must be a loopback address");
        }
        if self.public_addr == self.admin_addr {
            anyhow::bail!("DROP_PUBLIC_ADDR and DROP_ADMIN_ADDR must differ");
        }
        if self.default_ttl_secs == 0 || self.default_ttl_secs > self.max_ttl_secs {
            anyhow::bail!("DROP_DEFAULT_TTL_SECS must be between 1 and DROP_MAX_TTL_SECS");
        }
        if self.max_drops == 0 {
            anyhow::bail!("DROP_MAX_DROPS must be at least 1");
        }
        // 最大長（全部 4 バイト文字）のドロップが 1 つは入ること
        if self.max_total_bytes < MAX_TEXT_CHARS * 4 {
            anyhow::bail!(
                "DROP_MAX_TOTAL_BYTES must be at least {}",
                MAX_TEXT_CHARS * 4
            );
        }
        parse_remote_admin_hashes(self.remote_admin_token_sha256s.as_deref())?;
        Ok(())
    }

    /// 検証子をバイト列で返す（validate() で形式を確認済み）。
    pub fn remote_admin_hashes(&self) -> Vec<[u8; 32]> {
        parse_remote_admin_hashes(self.remote_admin_token_sha256s.as_deref()).unwrap_or_default()
    }

    pub fn limits(&self) -> Limits {
        Limits {
            max_drops: self.max_drops,
            max_total_bytes: self.max_total_bytes,
            default_ttl: Duration::from_secs(self.default_ttl_secs),
            max_ttl: Duration::from_secs(self.max_ttl_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_pairs(pairs: &[(&str, &str)]) -> anyhow::Result<Config> {
        let config: Config = envy::prefixed("DROP_")
            .from_iter(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn defaults() {
        let config = from_pairs(&[]).unwrap();
        assert_eq!(config.public_addr, "127.0.0.1:8470".parse().unwrap());
        assert_eq!(config.admin_addr, "127.0.0.1:8471".parse().unwrap());
        let limits = config.limits();
        assert_eq!(limits.default_ttl, Duration::from_secs(600));
        assert_eq!(limits.max_ttl, Duration::from_secs(3600));
        assert_eq!(limits.max_drops, 1000);
        assert_eq!(limits.max_total_bytes, 1024 * 1024);
    }

    #[test]
    fn overrides() {
        let config = from_pairs(&[
            ("DROP_PUBLIC_ADDR", "[::1]:9000"),
            ("DROP_ADMIN_ADDR", "127.0.0.1:9001"),
            ("DROP_DEFAULT_TTL_SECS", "60"),
            ("DROP_MAX_TTL_SECS", "120"),
            ("DROP_MAX_DROPS", "5"),
            ("DROP_MAX_TOTAL_BYTES", "65536"),
            ("UNRELATED", "ignored"),
        ])
        .unwrap();
        assert_eq!(config.public_addr, "[::1]:9000".parse().unwrap());
        assert_eq!(config.limits().max_drops, 5);
    }

    #[test]
    fn remote_admin_hashes_parse() {
        let hash = "ab".repeat(32);
        let config = from_pairs(&[("DROP_REMOTE_ADMIN_TOKEN_SHA256S", hash.as_str())]).unwrap();
        assert_eq!(config.remote_admin_hashes(), vec![[0xab; 32]]);
        // 未設定・空白だけは無効（空ベクタ）
        assert!(from_pairs(&[]).unwrap().remote_admin_hashes().is_empty());
        let blank = from_pairs(&[("DROP_REMOTE_ADMIN_TOKEN_SHA256S", "  ")]).unwrap();
        assert!(blank.remote_admin_hashes().is_empty());
        // 複数本（ローテーションの重ね期間）
        let two = format!("{hash},{}", "cd".repeat(32));
        let config = from_pairs(&[("DROP_REMOTE_ADMIN_TOKEN_SHA256S", two.as_str())]).unwrap();
        assert_eq!(config.remote_admin_hashes().len(), 2);
        // 形式が違うものは起動時に拒否する
        for bad in ["xyz", "ab".repeat(31).as_str(), "zz".repeat(32).as_str()] {
            assert!(
                from_pairs(&[("DROP_REMOTE_ADMIN_TOKEN_SHA256S", bad)]).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_unsafe_or_inconsistent_settings() {
        for pairs in [
            &[("DROP_PUBLIC_ADDR", "0.0.0.0:8470")][..],
            &[("DROP_ADMIN_ADDR", "192.0.2.1:8471")][..],
            &[("DROP_ADMIN_ADDR", "127.0.0.1:8470")][..],
            &[("DROP_DEFAULT_TTL_SECS", "0")][..],
            &[("DROP_DEFAULT_TTL_SECS", "7200")][..],
            &[("DROP_MAX_DROPS", "0")][..],
            &[("DROP_MAX_TOTAL_BYTES", "100")][..],
            &[("DROP_MAX_DROPS", "many")][..],
        ] {
            assert!(from_pairs(pairs).is_err(), "{pairs:?} should be rejected");
        }
    }
}
