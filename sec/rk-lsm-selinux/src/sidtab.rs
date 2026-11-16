//! The table of the security identifiers, as security/selinux/ss/sidtab.c of Linux.
//!
//! A security identifier (SID) is a number for a context. The SIDs 1 to 27 are the initial
//! SIDs, which the policy gives a context with its `sid` statements. The table gives the
//! next SIDs to the other contexts when the kernel first uses them. A context that the policy
//! does not accept can also have a SID, as its text, for example the label of a file that a
//! later policy can accept. Such a SID gives the context of the initial SID `unlabeled`.

use crate::policydb::{Context, Policydb, sym};
use crate::{POLICYCAP_NAMES, policydb::Level};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// The initial SIDs that the kernel uses, `SECINITSID_*` of Linux.
pub mod sid {
    /// The kernel and the tasks before a policy load.
    pub const KERNEL: u32 = 1;
    /// The objects of the security server, as the files of selinuxfs.
    pub const SECURITY: u32 = 2;
    /// The objects without a valid label.
    pub const UNLABELED: u32 = 3;
    /// The files without a label.
    pub const FILE: u32 = 5;
    /// The first process, with the policy capability `userspace_initial_context`.
    pub const INIT: u32 = 7;
    /// The file `/dev/null` of the kernel.
    pub const DEVNULL: u32 = 27;
}

/// The number of the initial SIDs, `SECINITSID_NUM` of Linux.
pub const NUM_INITIAL: u32 = 27;

/// The names of the initial SIDs that the kernel uses, `initial_sid_to_string` of Linux. The
/// other initial SIDs of a policy have no effect.
pub const INITIAL_NAMES: [Option<&str>; NUM_INITIAL as usize + 1] = [
    None,
    Some("kernel"),
    Some("security"),
    Some("unlabeled"),
    None,
    Some("file"),
    None,
    Some("init"),
    Some("any_socket"),
    Some("port"),
    Some("netif"),
    Some("netmsg"),
    Some("node"),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some("devnull"),
];

/// The context of a SID.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The context. A context that the policy does not accept has the default context.
    pub context: Context,
    /// The text of a context that the policy does not accept, or `None`.
    pub invalid: Option<String>,
}

/// A key of the index of the table: the canonical text of a valid context, or the text of a
/// context that the policy does not accept. Two contexts are the same if their keys are the
/// same, as `context_cmp` of Linux.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Valid(String),
    Invalid(String),
}

/// The table of a policy.
#[derive(Debug, Default)]
pub struct Sidtab {
    /// The contexts of the initial SIDs, at the index of the SID.
    initial: Vec<Option<Context>>,
    /// The other SIDs, from [`NUM_INITIAL`] plus 1.
    entries: Vec<Entry>,
    /// The SID of each context.
    index: BTreeMap<Key, u32>,
    /// A new policy replaces this table, and the new SIDs go to the new table.
    pub frozen: bool,
}

impl Sidtab {
    /// Makes the table of the policy `db` with its initial SIDs, as `policydb_load_isids` of
    /// Linux. Without the policy capability `userspace_initial_context`, the SID `init` has
    /// the context of the SID `kernel`.
    pub fn new(db: &Policydb) -> Option<Self> {
        let mut t =
            Self { initial: alloc::vec![None; NUM_INITIAL as usize + 1], ..Self::default() };
        let user_init = POLICYCAP_NAMES.iter().position(|&n| n == "userspace_initial_context");
        let user_init = user_init.is_some_and(|i| db.policycap(i as u32));
        for oc in &db.ocon.isid {
            let named = INITIAL_NAMES.get(oc.key as usize).is_some_and(Option::is_some);
            if !named || (oc.key == sid::INIT && !user_init) {
                continue;
            }
            t.set_initial(db, oc.key, oc.context.clone());
        }
        if !user_init && let Some(kernel) = t.initial[sid::KERNEL as usize].clone() {
            t.set_initial(db, sid::INIT, kernel);
        }
        if t.initial[sid::UNLABELED as usize].is_none() {
            rk_frame::println!("SELinux:  unable to load the initial SIDs");
            return None;
        }
        Some(t)
    }

    /// Gives the initial SID `sid` the context `c`. Two initial SIDs can have the same
    /// context, and the index keeps the lowest SID, as the lookup of Linux finds it.
    fn set_initial(&mut self, db: &Policydb, sid: u32, c: Context) {
        let e = self.index.entry(Key::Valid(db.context_to_string(&c))).or_insert(sid);
        *e = (*e).min(sid);
        self.initial[sid as usize] = Some(c);
    }

    /// The number of the SIDs that are not initial SIDs.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The context of the SID `sid`, as `sidtab_search_entry` of Linux. A SID that is not in
    /// the table, or without `force` a SID of a context that the policy does not accept, gives
    /// the context of the SID `unlabeled`.
    pub fn search(&self, sid: u32, force: bool) -> Option<Entry> {
        let entry = if sid > NUM_INITIAL {
            self.entries.get((sid - NUM_INITIAL - 1) as usize).cloned()
        } else {
            self.initial(sid)
        };
        match entry {
            Some(e) if e.invalid.is_none() || force => Some(e),
            _ => self.initial(sid::UNLABELED),
        }
    }

    /// The context of the initial SID `sid`.
    fn initial(&self, sid: u32) -> Option<Entry> {
        let c = self.initial.get(sid as usize)?.clone()?;
        Some(Entry { context: c, invalid: None })
    }

    /// The SID of a context, as `sidtab_context_to_sid` of Linux. A new context gets the next
    /// SID.
    pub fn context_to_sid(&mut self, db: &Policydb, entry: Entry) -> u32 {
        let key = match &entry.invalid {
            Some(text) => Key::Invalid(text.clone()),
            None => Key::Valid(db.context_to_string(&entry.context)),
        };
        if let Some(&sid) = self.index.get(&key) {
            return sid;
        }
        self.entries.push(entry);
        let sid = NUM_INITIAL + self.entries.len() as u32;
        self.index.insert(key, sid);
        sid
    }

    /// Copies the SIDs of this table to the table `new` of a new policy, as `sidtab_convert`
    /// of Linux. A context keeps its SID, and its user, role, type and levels get the values
    /// of the new policy for the same names. In enforcing mode, a context that the new policy
    /// does not accept becomes a text.
    pub fn convert(&self, old: &Policydb, db: &Policydb, new: &mut Sidtab, enforcing: bool) {
        rk_frame::println!("SELinux:  Converting {} SID table entries...", self.entries.len());
        let unlabeled = new.initial[sid::UNLABELED as usize].clone().unwrap_or_default();
        for (i, e) in self.entries.iter().enumerate() {
            let entry = match &e.invalid {
                Some(text) => match db.string_to_context(text, None) {
                    Some(c) => {
                        rk_frame::println!("SELinux:  Context {text} became valid (mapped).");
                        Entry { context: c, invalid: None }
                    }
                    None => e.clone(),
                },
                None => {
                    let text = old.context_to_string(&e.context);
                    let c = convert_context(old, db, &e.context, &unlabeled);
                    match c {
                        Some(c) if db.context_valid(&c) => Entry { context: c, invalid: None },
                        Some(c) if !enforcing => {
                            rk_frame::println!(
                                "SELinux:  Context {text} would be invalid if enforcing"
                            );
                            Entry { context: c, invalid: None }
                        }
                        _ => {
                            rk_frame::println!(
                                "SELinux:  Context {text} became invalid (unmapped)."
                            );
                            Entry { context: Context::default(), invalid: Some(text) }
                        }
                    }
                }
            };
            let key = match &entry.invalid {
                Some(text) => Key::Invalid(text.clone()),
                None => Key::Valid(db.context_to_string(&entry.context)),
            };
            let sid = NUM_INITIAL + 1 + i as u32;
            new.index.entry(key).or_insert(sid);
            new.entries.push(entry);
        }
    }
}

/// The context of the old policy `old` with the values of the new policy `new`, as
/// `convert_context` of Linux. A context of a policy without MLS gets the range of the SID
/// `unlabeled` of the new policy. A name that is not in the new policy gives `None`.
fn convert_context(
    old: &Policydb,
    new: &Policydb,
    c: &Context,
    unlabeled: &Context,
) -> Option<Context> {
    let value = |table: usize, v: u32| -> Option<u32> {
        new.names[table].get(old.name(table, v)?).copied()
    };
    let level = |l: &Level| -> Option<Level> {
        let mut out = Level { sens: value(sym::LEVELS, l.sens)?, ..Level::default() };
        for bit in l.cats.iter() {
            out.cats.set(value(sym::CATS, bit + 1)? - 1, true);
        }
        Some(out)
    };
    let mut n = Context {
        user: value(sym::USERS, c.user)?,
        role: value(sym::ROLES, c.role)?,
        ty: value(sym::TYPES, c.ty)?,
        range: Default::default(),
    };
    match (old.mls, new.mls) {
        (true, true) => {
            n.range.low = level(&c.range.low)?;
            n.range.high = level(&c.range.high)?;
        }
        (false, true) => n.range = unlabeled.range.clone(),
        _ => {}
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_gives_a_sid_to_each_context() {
        let db = Policydb::read(include_bytes!("../tests/rk_test.33.bin")).unwrap();
        let mut t = Sidtab::new(&db).unwrap();
        let text = |t: &Sidtab, sid: u32, force: bool| {
            let e = t.search(sid, force).unwrap();
            e.invalid.unwrap_or_else(|| db.context_to_string(&e.context))
        };
        assert_eq!(text(&t, sid::KERNEL, false), "system_u:system_r:kernel_t:s0-s1:c0.c2");
        assert_eq!(text(&t, sid::INIT, false), "system_u:system_r:kernel_t:s0-s1:c0.c2");
        assert_eq!(text(&t, sid::FILE, false), "system_u:object_r:unlabeled_t:s0");
        // The SID `fs` is not a SID of the kernel.
        assert_eq!(text(&t, 4, false), "system_u:object_r:unlabeled_t:s0");
        let c = |s: &str| Entry { context: db.string_to_context(s, None).unwrap(), invalid: None };
        assert_eq!(t.context_to_sid(&db, c("system_u:object_r:unlabeled_t:s0")), sid::UNLABELED);
        assert_eq!(t.context_to_sid(&db, c("system_u:object_r:etc_t:s0")), 28);
        assert_eq!(t.context_to_sid(&db, c("system_u:object_r:bin_t:s0")), 29);
        assert_eq!(t.context_to_sid(&db, c("system_u:object_r:sbin_t:s0")), 29);
        let bad = Entry { context: Context::default(), invalid: Some("a:b:c".into()) };
        assert_eq!(t.context_to_sid(&db, bad.clone()), 30);
        assert_eq!(t.context_to_sid(&db, bad), 30);
        assert_eq!(text(&t, 30, false), "system_u:object_r:unlabeled_t:s0");
        assert_eq!(text(&t, 30, true), "a:b:c");
        assert_eq!(text(&t, 31, true), "system_u:object_r:unlabeled_t:s0");
        // A new policy keeps the SIDs.
        let db35 = Policydb::read(include_bytes!("../tests/rk_test.35.bin")).unwrap();
        let mut new = Sidtab::new(&db35).unwrap();
        t.convert(&db, &db35, &mut new, true);
        assert_eq!(new.count(), 3);
        let e = new.search(29, false).unwrap();
        assert_eq!(db35.context_to_string(&e.context), "system_u:object_r:bin_t:s0");
        assert_eq!(new.context_to_sid(&db35, new.search(28, false).unwrap()), 28);
        assert_eq!(new.search(30, true).unwrap().invalid.as_deref(), Some("a:b:c"));
    }
}
