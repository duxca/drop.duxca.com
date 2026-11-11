//! メモリ内のドロップ置き場。
//!
//! 状態はこのプロセスのメモリだけに置く。再起動すれば全部消えるのが正しい性質。
//! 期限切れはアクセス時に遅延削除し、加えて [`Store::purge_expired`] を定期的に呼んで掃除する。
//! 期限切れのドロップは、まだ掃除されていなくても存在しないものとして扱う。

use crate::token::Token;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

/// 1 ドロップの本文の上限（Unicode スカラ値の数。バイト数ではない）。
pub const MAX_TEXT_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// 同時に存在できるドロップ数（未投稿も含む）。
    pub max_drops: usize,
    /// 預かり中の本文の合計バイト数（UTF-8）。
    pub max_total_bytes: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Empty,
    Filled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    Empty,
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    InvalidTtl,
    Text(TextError),
    TooManyDrops,
    StorageFull,
    Rng,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillError {
    NotFound,
    AlreadyFilled,
    Text(TextError),
    StorageFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeError {
    NotFound,
    NotFilled,
}

pub fn check_text(text: &str) -> Result<(), TextError> {
    if text.is_empty() {
        return Err(TextError::Empty);
    }
    if text.chars().count() > MAX_TEXT_CHARS {
        return Err(TextError::TooLong);
    }
    Ok(())
}

struct Entry {
    expires_at: Instant,
    text: Option<String>,
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        now < self.expires_at
    }

    fn text_bytes(&self) -> usize {
        self.text.as_ref().map_or(0, String::len)
    }
}

pub struct Store {
    limits: Limits,
    entries: HashMap<Token, Entry>,
    /// `entries` の本文バイト数の合計。
    text_bytes: usize,
}

impl Store {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            text_bytes: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ドロップを発行する。`text` があれば投稿済み状態で作る（先入れ）。
    pub fn issue(
        &mut self,
        now: Instant,
        ttl_secs: Option<u64>,
        text: Option<String>,
    ) -> Result<(Token, Duration), IssueError> {
        let ttl = match ttl_secs {
            None => self.limits.default_ttl,
            Some(0) => return Err(IssueError::InvalidTtl),
            Some(secs) if Duration::from_secs(secs) > self.limits.max_ttl => {
                return Err(IssueError::InvalidTtl)
            }
            Some(secs) => Duration::from_secs(secs),
        };
        if let Some(text) = &text {
            check_text(text).map_err(IssueError::Text)?;
        }
        let bytes = text.as_ref().map_or(0, String::len);
        if self.entries.len() >= self.limits.max_drops || !self.fits(bytes) {
            self.purge_expired(now);
        }
        if self.entries.len() >= self.limits.max_drops {
            return Err(IssueError::TooManyDrops);
        }
        if !self.fits(bytes) {
            return Err(IssueError::StorageFull);
        }
        let token = loop {
            let token = Token::generate().map_err(|_| IssueError::Rng)?;
            if !self.entries.contains_key(&token) {
                break token;
            }
        };
        self.text_bytes += bytes;
        self.entries.insert(
            token,
            Entry {
                expires_at: now + ttl,
                text,
            },
        );
        Ok((token, ttl))
    }

    pub fn status(&mut self, now: Instant, token: &Token) -> Option<Status> {
        self.live(now, token).map(|entry| match entry.text {
            Some(_) => Status::Filled,
            None => Status::Empty,
        })
    }

    /// 1 回だけ書き込む。
    pub fn fill(&mut self, now: Instant, token: &Token, text: String) -> Result<(), FillError> {
        match self.status(now, token) {
            None => return Err(FillError::NotFound),
            Some(Status::Filled) => return Err(FillError::AlreadyFilled),
            Some(Status::Empty) => {}
        }
        check_text(&text).map_err(FillError::Text)?;
        let bytes = text.len();
        if !self.fits(bytes) {
            self.purge_expired(now);
            if !self.fits(bytes) {
                return Err(FillError::StorageFull);
            }
        }
        let entry = self.entries.get_mut(token).ok_or(FillError::NotFound)?;
        entry.text = Some(text);
        self.text_bytes += bytes;
        Ok(())
    }

    /// 値を 1 回だけ取り出し、その場で削除する。未投稿なら何も変えない。
    pub fn take(&mut self, now: Instant, token: &Token) -> Result<String, TakeError> {
        match self.status(now, token) {
            None => Err(TakeError::NotFound),
            Some(Status::Empty) => Err(TakeError::NotFilled),
            Some(Status::Filled) => self
                .evict(token)
                .and_then(|entry| entry.text)
                .ok_or(TakeError::NotFound),
        }
    }

    /// 明示破棄。生きているドロップを消したときだけ true。
    pub fn remove(&mut self, now: Instant, token: &Token) -> bool {
        self.live(now, token).is_some() && self.evict(token).is_some()
    }

    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let mut freed = 0;
        self.entries.retain(|_, entry| {
            let keep = entry.is_live(now);
            if !keep {
                freed += entry.text_bytes();
            }
            keep
        });
        self.text_bytes -= freed;
        before - self.entries.len()
    }

    #[cfg(test)]
    pub fn text_bytes(&self) -> usize {
        self.text_bytes
    }

    fn fits(&self, bytes: usize) -> bool {
        self.text_bytes + bytes <= self.limits.max_total_bytes
    }

    /// 生きているエントリを返す。期限切れならその場で消して None。
    fn live(&mut self, now: Instant, token: &Token) -> Option<&mut Entry> {
        if self.entries.get(token)?.is_live(now) {
            return self.entries.get_mut(token);
        }
        self.evict(token);
        None
    }

    fn evict(&mut self, token: &Token) -> Option<Entry> {
        let entry = self.entries.remove(token)?;
        self.text_bytes -= entry.text_bytes();
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_drops: 3,
            max_total_bytes: 8 * 1024,
            default_ttl: Duration::from_secs(600),
            max_ttl: Duration::from_secs(3600),
        }
    }

    #[test]
    fn text_length_counts_unicode_scalar_values() {
        assert_eq!(check_text(""), Err(TextError::Empty));
        assert_eq!(check_text(&"a".repeat(MAX_TEXT_CHARS)), Ok(()));
        assert_eq!(
            check_text(&"a".repeat(MAX_TEXT_CHARS + 1)),
            Err(TextError::TooLong)
        );
        // 3 バイト文字・4 バイト文字でも 1024 字までは通る
        assert_eq!(check_text(&"あ".repeat(MAX_TEXT_CHARS)), Ok(()));
        assert_eq!(check_text(&"🔑".repeat(MAX_TEXT_CHARS)), Ok(()));
        assert_eq!(
            check_text(&"🔑".repeat(MAX_TEXT_CHARS + 1)),
            Err(TextError::TooLong)
        );
    }

    #[test]
    fn fill_once_then_take_once() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        let (token, ttl) = store.issue(now, None, None).unwrap();
        assert_eq!(ttl, Duration::from_secs(600));
        assert_eq!(store.status(now, &token), Some(Status::Empty));
        assert_eq!(store.take(now, &token), Err(TakeError::NotFilled));
        assert_eq!(store.status(now, &token), Some(Status::Empty));

        store.fill(now, &token, "v".into()).unwrap();
        assert_eq!(store.text_bytes(), 1);
        assert_eq!(
            store.fill(now, &token, "w".into()),
            Err(FillError::AlreadyFilled)
        );
        assert_eq!(store.take(now, &token), Ok("v".into()));
        assert_eq!(store.take(now, &token), Err(TakeError::NotFound));
        assert_eq!(store.text_bytes(), 0);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn rejected_text_is_not_stored() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        let (token, _) = store.issue(now, None, None).unwrap();
        assert_eq!(
            store.fill(now, &token, "x".repeat(MAX_TEXT_CHARS + 1)),
            Err(FillError::Text(TextError::TooLong))
        );
        assert_eq!(
            store.fill(now, &token, String::new()),
            Err(FillError::Text(TextError::Empty))
        );
        assert_eq!(store.status(now, &token), Some(Status::Empty));
        assert_eq!(store.text_bytes(), 0);
    }

    #[test]
    fn expired_drops_are_gone_everywhere() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        let (a, _) = store.issue(now, Some(10), None).unwrap();
        let (b, _) = store.issue(now, Some(10), Some("b".into())).unwrap();
        let (c, _) = store.issue(now, Some(10), Some("c".into())).unwrap();
        let later = now + Duration::from_secs(10);
        assert_eq!(store.status(later, &a), None);
        assert_eq!(store.take(later, &b), Err(TakeError::NotFound));
        assert!(!store.remove(later, &c));
        assert_eq!(store.len(), 0);
        assert_eq!(store.text_bytes(), 0);
    }

    #[test]
    fn purge_removes_only_expired() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        store.issue(now, Some(5), Some("old".into())).unwrap();
        let (keep, _) = store.issue(now, Some(60), Some("new".into())).unwrap();
        assert_eq!(store.purge_expired(now + Duration::from_secs(5)), 1);
        assert_eq!(store.len(), 1);
        assert_eq!(store.text_bytes(), 3);
        assert_eq!(store.status(now, &keep), Some(Status::Filled));
    }

    #[test]
    fn ttl_bounds() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        assert_eq!(
            store.issue(now, Some(0), None).err(),
            Some(IssueError::InvalidTtl)
        );
        assert_eq!(
            store.issue(now, Some(3601), None).err(),
            Some(IssueError::InvalidTtl)
        );
        assert_eq!(
            store.issue(now, Some(3600), None).unwrap().1,
            Duration::from_secs(3600)
        );
        assert_eq!(
            store.issue(now, Some(u64::MAX), None).err(),
            Some(IssueError::InvalidTtl)
        );
    }

    #[test]
    fn drop_count_limit_purges_expired_before_refusing() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        for _ in 0..3 {
            store.issue(now, Some(1), None).unwrap();
        }
        assert_eq!(
            store.issue(now, None, None).err(),
            Some(IssueError::TooManyDrops)
        );
        let later = now + Duration::from_secs(1);
        assert!(store.issue(later, None, None).is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn total_bytes_limit() {
        let mut store = Store::new(Limits {
            max_total_bytes: 10,
            ..limits()
        });
        let now = Instant::now();
        let (a, _) = store.issue(now, None, None).unwrap();
        let (b, _) = store.issue(now, None, Some("12345678".into())).unwrap();
        assert_eq!(
            store.fill(now, &a, "abc".into()),
            Err(FillError::StorageFull)
        );
        assert_eq!(store.status(now, &a), Some(Status::Empty));
        assert_eq!(
            store.issue(now, None, Some("abc".into())).err(),
            Some(IssueError::StorageFull)
        );
        store.take(now, &b).unwrap();
        store.fill(now, &a, "abc".into()).unwrap();
        assert_eq!(store.text_bytes(), 3);
    }

    #[test]
    fn remove_live_drop() {
        let mut store = Store::new(limits());
        let now = Instant::now();
        let (token, _) = store.issue(now, None, Some("x".into())).unwrap();
        assert!(store.remove(now, &token));
        assert!(!store.remove(now, &token));
        assert_eq!(store.text_bytes(), 0);
    }
}
