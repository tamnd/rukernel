//! The DFA of a policy, as security/apparmor/match.c of Linux.
//!
//! The policy compiler gives each rule set as a DFA in the tables of flex: a table of the
//! default states, a table of the bases, the tables of the next and the check states, the
//! table of the equivalence classes and the accept tables. The kernel walks the DFA with the
//! bytes of a path and reads the permissions of the last state.

use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::inode::Result;

/// A state of a DFA, `aa_state_t` of Linux.
pub type State = u32;

/// The state that matches nothing, `DFA_NOMATCH`.
pub const NOMATCH: State = 0;

/// The first state, `DFA_START`.
pub const START: State = 1;

/// The magic number of the header of the tables, `YYTH_MAGIC`.
const MAGIC: u32 = 0x1B5E_783D;

/// The header flag of the states that take the transitions of their default state.
const TH_FLAG_DIFF_ENCODE: u16 = 1;
/// The header flag of the out of band transitions.
const TH_FLAG_OOB_TRANS: u16 = 2;

/// The IDs of the tables, `YYTD_ID_*` of Linux, less one.
const ID_ACCEPT: usize = 0;
const ID_BASE: usize = 1;
const ID_CHK: usize = 2;
const ID_DEF: usize = 3;
const ID_EC: usize = 4;
const ID_ACCEPT2: usize = 6;
const ID_NXT: usize = 7;
const ID_MAX: usize = 8;

/// The sizes of the elements of a table, `YYTD_DATA*`.
pub const DATA8: u16 = 1;
/// 16-bit elements.
pub const DATA16: u16 = 2;
/// 32-bit elements.
pub const DATA32: u16 = 4;

/// The flags of a base entry, `MATCH_FLAG_*`.
const MATCH_FLAG_DIFF_ENCODE: u32 = 0x8000_0000;
const MARK_DIFF_ENCODE: u32 = 0x4000_0000;
const MATCH_FLAG_OOB_TRANSITION: u32 = 0x2000_0000;
const MARK_DIFF_ENCODE_VERIFIED: u32 = 0x1000_0000;
const MATCH_FLAGS_MASK: u32 = 0xff00_0000;
const MATCH_FLAGS_INVALID: u32 =
    MATCH_FLAGS_MASK & !(MATCH_FLAG_DIFF_ENCODE | MATCH_FLAG_OOB_TRANSITION);

/// The accept flags of the unpack, `TO_ACCEPT1_FLAG` and `TO_ACCEPT2_FLAG` of Linux.
pub fn accept_flags(accept1: u16, accept2: u16) -> u32 {
    u32::from(accept1 & 0x3f) | (u32::from(accept2 & 0x3f) << ID_ACCEPT2)
}

/// The index of the transitions of a base entry.
fn base_idx(b: u32) -> usize {
    (b & 0xff_ffff) as usize
}

/// The size of a table with its header of 12 bytes, aligned to 8 bytes, `table_size` of Linux.
fn table_size(len: usize, el: usize) -> Option<usize> {
    let size = len.checked_mul(el)?.checked_add(12)?;
    size.checked_add(7).map(|s| s & !7)
}

/// A DFA, `struct aa_dfa` of Linux. The tables with 16-bit elements are made 32-bit.
#[derive(Clone, Debug, Default)]
pub struct Dfa {
    /// The flags of the header.
    pub flags: u16,
    /// The tables by ID. The table of the equivalence classes keeps its bytes as `u32`.
    tables: [Option<Vec<u32>>; ID_MAX + 1],
}

impl Dfa {
    /// Unpacks the tables of `blob`, as `aa_dfa_unpack` of Linux with `DFA_FLAG_VERIFY_STATES`.
    /// `flags` gives the element sizes that the accept tables can have ([`accept_flags`]).
    ///
    /// # Errors
    ///
    /// Gives `EPROTO` for tables that are not correct.
    pub fn unpack(blob: &[u8], flags: u32) -> Result<Self> {
        let be16 = |b: &[u8], at: usize| u16::from_be_bytes([b[at], b[at + 1]]);
        let be32 =
            |b: &[u8], at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        // The header: magic, header size, set size, flags and the version text.
        if blob.len() < 14 || be32(blob, 0) != MAGIC {
            return Err(Errno::EPROTO);
        }
        let hsize = be32(blob, 4) as usize;
        if blob.len() < hsize || hsize < 14 {
            return Err(Errno::EPROTO);
        }
        let mut dfa = Self { flags: be16(blob, 12), ..Self::default() };
        if dfa.flags & !(TH_FLAG_DIFF_ENCODE | TH_FLAG_OOB_TRANS) != 0 {
            return Err(Errno::EPROTO);
        }
        let mut data = &blob[hsize..];
        while !data.is_empty() {
            if data.len() < 12 {
                return Err(Errno::EPROTO);
            }
            // The IDs in the blob start at 1.
            let id = usize::from(be16(data, 0)).wrapping_sub(1);
            let td_flags = be16(data, 2);
            let len = be32(data, 8) as usize;
            if id > ID_MAX || len == 0 {
                return Err(Errno::EPROTO);
            }
            let el = match td_flags {
                DATA8 => 1,
                DATA16 => 2,
                DATA32 => 4,
                _ => return Err(Errno::EPROTO),
            };
            let size = table_size(len, el).ok_or(Errno::EPROTO)?;
            if data.len() < 12 + len * el {
                return Err(Errno::EPROTO);
            }
            let ok = match id {
                ID_ACCEPT => u32::from(td_flags) & (flags & 0x3f) != 0,
                ID_ACCEPT2 => u32::from(td_flags) & ((flags >> ID_ACCEPT2) & 0x3f) != 0,
                ID_BASE => td_flags == DATA32,
                ID_DEF | ID_NXT | ID_CHK => td_flags == DATA16 || td_flags == DATA32,
                ID_EC => td_flags == DATA8,
                _ => false,
            };
            if !ok || dfa.tables[id].is_some() {
                return Err(Errno::EPROTO);
            }
            let body = &data[12..12 + len * el];
            let mut table = Vec::new();
            table.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
            match el {
                1 => table.extend(body.iter().map(|&b| u32::from(b))),
                2 => table.extend((0..len).map(|i| u32::from(be16(body, 2 * i)))),
                _ => table.extend((0..len).map(|i| be32(body, 4 * i))),
            }
            dfa.tables[id] = Some(table);
            data = data.get(size..).unwrap_or(&[]);
        }
        dfa.verify_headers(flags)?;
        dfa.verify()?;
        Ok(dfa)
    }

    fn table(&self, id: usize) -> &[u32] {
        self.tables[id].as_deref().unwrap_or(&[])
    }

    /// The count of the states.
    pub fn states(&self) -> usize {
        self.table(ID_BASE).len()
    }

    /// The accept table.
    pub fn accept(&self) -> &[u32] {
        self.table(ID_ACCEPT)
    }

    /// The second accept table.
    pub fn accept2(&self) -> &[u32] {
        self.table(ID_ACCEPT2)
    }

    /// Tells if the DFA has the second accept table.
    pub fn has_accept2(&self) -> bool {
        self.tables[ID_ACCEPT2].is_some()
    }

    /// Adds a second accept table of zeros, for a policy whose permissions are in their own
    /// table, as `unpack_pdb` of Linux.
    pub fn add_accept2(&mut self) {
        self.tables[ID_ACCEPT2] = Some(vec![0; self.accept().len()]);
    }

    /// Sets the accept tables to the index `state * factor` of the permission table, as
    /// `remap_dfa_accept` of Linux. A factor of 2 marks the pairs of the owner.
    pub fn remap_accept(&mut self, factor: u32) {
        let n = self.states();
        let accept: Vec<u32> = (0..n as u32).map(|s| s * factor).collect();
        let owner = u32::from(factor > 1) * ACCEPT_FLAG_OWNER;
        self.tables[ID_ACCEPT] = Some(accept);
        self.tables[ID_ACCEPT2] = Some(vec![owner; n]);
    }

    /// Checks the sizes of the tables, as `verify_table_headers` of Linux.
    fn verify_headers(&self, flags: u32) -> Result<()> {
        let t = &self.tables;
        if t[ID_DEF].is_none() || t[ID_BASE].is_none() || t[ID_NXT].is_none() || t[ID_CHK].is_none()
        {
            return Err(Errno::EPROTO);
        }
        let states = self.states();
        let same = |id: usize| t[id].as_ref().is_some_and(|x| x.len() == states);
        let bad = (flags & 0x3f != 0 && !same(ID_ACCEPT))
            || ((flags >> ID_ACCEPT2) & 0x3f != 0 && !same(ID_ACCEPT2))
            || !same(ID_DEF)
            || self.table(ID_NXT).len() != self.table(ID_CHK).len()
            || t[ID_EC].as_ref().is_some_and(|e| e.len() != 256);
        if bad { Err(Errno::EPROTO) } else { Ok(()) }
    }

    /// Checks that the states and the transitions are in bounds, and that the chains of the
    /// states with diff encoding end, as `verify_dfa` of Linux.
    fn verify(&mut self) -> Result<()> {
        let states = self.states();
        let trans = self.table(ID_NXT).len();
        if states < 2 {
            return Err(Errno::EPROTO);
        }
        let def = self.table(ID_DEF);
        let base = self.table(ID_BASE);
        for i in 0..states {
            let b = base[i];
            let bad = def[i] as usize >= states
                || b & MATCH_FLAGS_INVALID != 0
                || (b & MATCH_FLAG_DIFF_ENCODE != 0 && self.flags & TH_FLAG_DIFF_ENCODE == 0)
                || (b & MATCH_FLAG_OOB_TRANSITION != 0
                    && (base_idx(b) < 1 || self.flags & TH_FLAG_OOB_TRANS == 0))
                || base_idx(b) + 255 >= trans;
            if bad {
                return Err(Errno::EPROTO);
            }
        }
        let next = self.table(ID_NXT);
        let chk = self.table(ID_CHK);
        if next.iter().chain(chk).any(|&s| s as usize >= states) {
            return Err(Errno::EPROTO);
        }
        let def = def.to_vec();
        let base = self.tables[ID_BASE].as_mut().ok_or(Errno::EPROTO)?;
        for i in 0..states {
            let mut j = i;
            while base[j] & MATCH_FLAG_DIFF_ENCODE != 0 && base[j] & MARK_DIFF_ENCODE_VERIFIED == 0
            {
                if base[j] & MARK_DIFF_ENCODE != 0 {
                    return Err(Errno::EPROTO);
                }
                let k = def[j] as usize;
                if j == k {
                    return Err(Errno::EPROTO);
                }
                base[j] |= MARK_DIFF_ENCODE;
                j = k;
            }
            let mut j = i;
            while base[j] & MATCH_FLAG_DIFF_ENCODE != 0 {
                let k = def[j] as usize;
                if j < i {
                    break;
                }
                base[j] &= !MARK_DIFF_ENCODE;
                base[j] |= MARK_DIFF_ENCODE_VERIFIED;
                j = k;
            }
        }
        Ok(())
    }

    /// One step on the class `c`, as the macro `match_char` of Linux. A state with diff
    /// encoding that has no transition on `c` takes the transitions of its default state.
    fn step(&self, mut state: State, c: usize) -> State {
        let def = self.table(ID_DEF);
        let base = self.table(ID_BASE);
        let next = self.table(ID_NXT);
        let chk = self.table(ID_CHK);
        loop {
            let b = base[state as usize];
            let pos = base_idx(b).wrapping_add(c);
            if chk.get(pos) == Some(&state) {
                return next[pos];
            }
            state = def[state as usize];
            if b & MATCH_FLAG_DIFF_ENCODE == 0 {
                return state;
            }
        }
    }

    /// The class of the byte `c`.
    fn class(&self, c: u8) -> usize {
        match &self.tables[ID_EC] {
            Some(ec) => ec[usize::from(c)] as usize,
            None => usize::from(c),
        }
    }

    /// The state after the byte `c`, `aa_dfa_next` of Linux.
    pub fn next(&self, state: State, c: u8) -> State {
        self.step(state, self.class(c))
    }

    /// The state after the bytes `s`, `aa_dfa_match_len` of Linux.
    pub fn match_bytes(&self, start: State, s: &[u8]) -> State {
        if start == NOMATCH {
            return NOMATCH;
        }
        s.iter().fold(start, |st, &c| self.step(st, self.class(c)))
    }

    /// The state after the out of band transition, `aa_dfa_outofband_transition` of Linux.
    pub fn outofband(&self, state: State) -> State {
        if self.table(ID_BASE)[state as usize] & MATCH_FLAG_OOB_TRANSITION == 0 {
            return NOMATCH;
        }
        self.step(state, usize::MAX)
    }
}

/// The flag of the second accept table for a pair of entries of the owner and the others.
pub const ACCEPT_FLAG_OWNER: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with its header, in the format of the policy compiler.
    fn table(id: u16, flags: u16, data: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(id.to_be_bytes());
        out.extend(flags.to_be_bytes());
        out.extend(0u32.to_be_bytes());
        out.extend((data.len() as u32).to_be_bytes());
        for &d in data {
            match flags {
                DATA8 => out.push(d as u8),
                DATA16 => out.extend((d as u16).to_be_bytes()),
                _ => out.extend(d.to_be_bytes()),
            }
        }
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out
    }

    /// A DFA with three states that matches "ab": 1 -a-> 2 -b-> 3. State 3 accepts with 7.
    pub(crate) fn ab_dfa() -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend(MAGIC.to_be_bytes());
        blob.extend(16u32.to_be_bytes());
        blob.extend(0u32.to_be_bytes());
        blob.extend(0u16.to_be_bytes());
        blob.extend([0, 0]);
        // The transitions of the states 1 and 2 are at 0 and 1 in next and check. Each state
        // needs 256 entries after its base.
        let mut next = vec![0u32; 258];
        let mut chk = vec![0u32; 258];
        next[usize::from(b'a')] = 2;
        chk[usize::from(b'a')] = 1;
        next[1 + usize::from(b'b')] = 3;
        chk[1 + usize::from(b'b')] = 2;
        blob.extend(table(1, DATA32, &[0, 0, 0, 7]));
        blob.extend(table(2, DATA32, &[0, 0, 1, 2]));
        blob.extend(table(3, DATA16, &chk));
        blob.extend(table(4, DATA16, &[0, 0, 0, 0]));
        blob.extend(table(8, DATA16, &next));
        blob
    }

    #[test]
    fn a_dfa_unpacks_and_matches() {
        let dfa = Dfa::unpack(&ab_dfa(), accept_flags(DATA32, 0)).unwrap();
        assert_eq!(dfa.states(), 4);
        assert_eq!(dfa.match_bytes(START, b"ab"), 3);
        assert_eq!(dfa.accept()[3], 7);
        assert_eq!(dfa.match_bytes(START, b"ac"), NOMATCH);
        assert_eq!(dfa.next(START, b'a'), 2);
        assert_eq!(dfa.outofband(START), NOMATCH);
        // The accept table must be there.
        assert_eq!(Dfa::unpack(&ab_dfa(), accept_flags(DATA32, DATA32)).err(), Some(Errno::EPROTO));
        let mut bad = ab_dfa();
        bad[0] = 0;
        assert_eq!(Dfa::unpack(&bad, accept_flags(DATA32, 0)).err(), Some(Errno::EPROTO));
        assert_eq!(
            Dfa::unpack(&ab_dfa()[..40], accept_flags(DATA32, 0)).err(),
            Some(Errno::EPROTO)
        );
    }
}
