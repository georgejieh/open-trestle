//! A small in-memory ledger with pluggable storage and audit hooks.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Display, Formatter};
use std::io::{Read as _, Write};
use std::sync::{Arc, Mutex};
use std::{cmp::Ordering, error::Error as StdError};

use crate::money::*;
use crate::storage::backend::{Backend, MemoryBackend as Memory};
use serde::{Deserialize, Serialize};

extern crate alloc;
extern crate core as std_core;

pub const MAX_ENTRIES: usize = 4096;
const DEFAULT_CURRENCY: &str = "USD";
pub static VERSION: &str = "2.1";
static mut LOAD_COUNT: u32 = 0;

pub type AccountId = u64;
pub type Shared<T> = Arc<Mutex<T>>;
type Result<T> = std::result::Result<T, LedgerError>;

/// Errors raised by ledger operations.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerError {
    UnknownAccount(AccountId),
    Overdrawn { account: AccountId, short_by: i64 },
    Frozen,
    Storage(String),
}

impl Display for LedgerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::UnknownAccount(id) => write!(f, "unknown account {}", id),
            LedgerError::Overdrawn { account, short_by } => {
                write!(f, "account {} short by {}", account, short_by)
            }
            LedgerError::Frozen => f.write_str("frozen"),
            LedgerError::Storage(msg) => write!(f, "storage: {}", msg),
        }
    }
}

impl StdError for LedgerError {}

impl From<std::io::Error> for LedgerError {
    fn from(err: std::io::Error) -> Self {
        LedgerError::Storage(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: u64,
    pub account: AccountId,
    pub amount: i64,
    pub memo: Option<String>,
    pub(crate) posted: bool,
    tags: Vec<String>,
}

#[derive(Default)]
pub struct Totals {
    pub credits: i64,
    pub debits: i64,
}

pub struct Marker;

pub struct Pair(pub i64, i64);

pub struct Ledger<B: Backend = Memory> {
    backend: B,
    accounts: HashMap<AccountId, Account>,
    entries: BTreeMap<u64, Entry>,
    hooks: Vec<Box<dyn Hook + Send>>,
    next_id: u64,
}

struct Account {
    id: AccountId,
    balance: i64,
    frozen: bool,
}

pub union Bits {
    pub whole: u64,
    pub halves: [u32; 2],
}

pub trait Hook {
    const NAME: &'static str;
    type Output;

    fn before(&self, entry: &Entry) -> bool;

    fn after(&self, entry: &Entry) {
        let _ = entry;
    }

    fn summary(&self) -> Self::Output;
}

pub trait Auditor: Hook + Send + Sync {
    fn audit<E: StdError>(&self, err: &E) -> String
    where
        E: fmt::Debug;
}

pub(crate) trait Visitor<'a, T: 'a> {
    fn visit(&mut self, item: &'a T);
}

impl Entry {
    pub const EMPTY_TAG: &'static str = "";

    pub fn new(id: u64, account: AccountId, amount: i64) -> Self {
        Entry {
            id,
            account,
            amount,
            memo: None,
            posted: false,
            tags: Vec::new(),
        }
    }

    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    pub(crate) fn is_credit(&self) -> bool {
        self.amount > 0
    }

    fn tag_count(&self) -> usize {
        self.tags.len()
    }
}

impl Default for Entry {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl<B: Backend> Ledger<B> {
    pub fn new(backend: B) -> Self {
        let mut ledger = Ledger {
            backend,
            accounts: HashMap::new(),
            entries: BTreeMap::new(),
            hooks: Vec::new(),
            next_id: 1,
        };
        ledger.load().expect("backend must load");
        ledger
    }

    pub fn open_account(&mut self, id: AccountId) -> &mut Account {
        self.accounts.entry(id).or_insert_with(|| Account {
            id,
            balance: 0,
            frozen: false,
        })
    }

    pub fn post(&mut self, account: AccountId, amount: i64) -> Result<u64> {
        let balance = self
            .accounts
            .get(&account)
            .map(|a| a.balance)
            .ok_or(LedgerError::UnknownAccount(account))?;
        if balance + amount < 0 {
            return Err(LedgerError::Overdrawn {
                account,
                short_by: -(balance + amount),
            });
        }
        let id = self.allocate_id();
        let entry = Entry::new(id, account, amount).with_memo("posted");
        for hook in self.hooks.iter() {
            if !hook.before(&entry) {
                return Err(LedgerError::Frozen);
            }
        }
        self.backend.write(id, &entry)?;
        self.entries.insert(id, entry);
        self.accounts.get_mut(&account).unwrap().balance += amount;
        Ok(id)
    }

    fn allocate_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn load(&mut self) -> Result<()> {
        unsafe {
            LOAD_COUNT += 1;
        }
        for entry in self.backend.read_all()? {
            self.entries.insert(entry.id, entry);
        }
        Ok(())
    }

    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        for entry in self.entries.values() {
            if entry.is_credit() {
                totals.credits += entry.amount;
            } else {
                totals.debits -= entry.amount;
            }
        }
        totals
    }

    pub fn add_hook<H>(&mut self, hook: H)
    where
        H: Hook + Send + 'static,
    {
        self.hooks.push(Box::new(hook));
    }
}

impl<B> Drop for Ledger<B>
where
    B: Backend,
{
    fn drop(&mut self) {
        let _ = self.backend.flush();
    }
}

impl<'a> Visitor<'a, Entry> for Totals {
    fn visit(&mut self, item: &'a Entry) {
        if item.is_credit() {
            self.credits += item.amount;
        }
    }
}

pub struct CountingHook {
    seen: usize,
}

impl Hook for CountingHook {
    const NAME: &'static str = "counting";
    type Output = usize;

    fn before(&self, entry: &Entry) -> bool {
        entry.amount != 0
    }

    fn summary(&self) -> usize {
        self.seen
    }
}

pub mod report {
    use super::{Entry, Ledger};
    use crate::storage::backend::Backend;

    pub const WIDTH: usize = 72;

    pub fn render<B: Backend>(ledger: &Ledger<B>) -> String {
        let mut lines = Vec::new();
        for (id, entry) in ledger.entries.iter() {
            lines.push(format_line(*id, entry));
        }
        lines.join("\n")
    }

    fn format_line(id: u64, entry: &Entry) -> String {
        format!("{:>6} {:>10}", id, entry.amount)
    }

    pub mod csv {
        pub fn header() -> &'static str {
            "id,amount"
        }
    }
}

mod tests_support;

macro_rules! entry {
    ($id:expr, $amount:expr) => {
        Entry::new($id, 1, $amount)
    };
}

pub fn compare(a: &Entry, b: &Entry) -> Ordering {
    a.amount.cmp(&b.amount).then_with(|| a.id.cmp(&b.id))
}

pub async fn sync_remote<T: Read>(source: &mut T) -> Result<usize> {
    let mut buffer = String::new();
    source.read_to_string(&mut buffer)?;
    let parsed: Vec<Entry> = serde_json::from_str(&buffer).map_err(|e| LedgerError::Storage(e.to_string()))?;
    Ok(parsed.len())
}

pub fn largest<'a>(entries: &'a [Entry]) -> Option<&'a Entry> {
    entries.iter().max_by(|x, y| compare(x, y))
}

fn make_adder(n: i64) -> impl Fn(i64) -> i64 {
    move |x| x + n
}

extern "C" {
    fn external_checksum(data: *const u8, len: usize) -> u32;
    static EXTERNAL_LIMIT: u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posts_credit() {
        let mut ledger = Ledger::new(Memory::default());
        ledger.open_account(7);
        let id = ledger.post(7, 50).unwrap();
        assert_eq!(id, 1);
        let e = entry!(2, 10);
        assert!(e.is_credit());
    }

    #[test]
    #[should_panic]
    fn rejects_overdraft() {
        let mut ledger: Ledger = Ledger::new(Memory::default());
        ledger.open_account(1);
        ledger.post(1, -5).unwrap();
    }
}

fn main() {
    let ledger = Ledger::new(Memory::default());
    let total = crate::report::render(&ledger);
    let size = std::mem::size_of::<Entry>();
    let adder = make_adder(3);
    println!("{} {} {}", total, size, adder(1));
    let marker = Marker;
    let pair = Pair(1, 2);
    let _ = (marker, pair);
}
