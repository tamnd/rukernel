//! The text of a security context, as `context_struct_to_string` and
//! `string_to_context_struct` of security/selinux/ss/services.c and the MLS part of
//! security/selinux/ss/mls.c of Linux.
//!
//! A context is `user:role:type`, and with MLS also `:range`. A range is a low level, then
//! `-` and a high level if the two levels are not equal. A level is a sensitivity, then `:`
//! and the categories, if there are categories. A run of three or more categories is written
//! `cA.cB`, and the other categories are separated by `,`.

use crate::policydb::{Context, Level, Policydb, Range, sym};
use alloc::string::String;

impl Policydb {
    /// The name of the value `value` of the table `table`, or an empty name.
    fn sym_name(&self, table: usize, value: u32) -> &str {
        self.name(table, value).unwrap_or_default()
    }

    /// The text of the context `c`, as `context_struct_to_string` of Linux.
    pub fn context_to_string(&self, c: &Context) -> String {
        let mut s = String::new();
        s.push_str(self.sym_name(sym::USERS, c.user));
        s.push(':');
        s.push_str(self.sym_name(sym::ROLES, c.role));
        s.push(':');
        s.push_str(self.sym_name(sym::TYPES, c.ty));
        if self.mls {
            s.push(':');
            self.write_level(&mut s, &c.range.low);
            if c.range.low != c.range.high {
                s.push('-');
                self.write_level(&mut s, &c.range.high);
            }
        }
        s
    }

    /// Writes a level, as `mls_sid_to_context` of Linux.
    fn write_level(&self, s: &mut String, level: &Level) {
        s.push_str(self.sym_name(sym::LEVELS, level.sens));
        let (mut head, mut prev) = (-2_i64, -2_i64);
        for bit in level.cats.iter() {
            let i = i64::from(bit);
            if i - prev > 1 {
                if prev != head {
                    s.push(if prev - head > 1 { '.' } else { ',' });
                    s.push_str(self.sym_name(sym::CATS, prev as u32 + 1));
                }
                s.push(if prev < 0 { ':' } else { ',' });
                s.push_str(self.sym_name(sym::CATS, bit + 1));
                head = i;
            }
            prev = i;
        }
        if prev != head {
            s.push(if prev - head > 1 { '.' } else { ',' });
            s.push_str(self.sym_name(sym::CATS, prev as u32 + 1));
        }
    }

    /// Reads the context in the text `text`, as `string_to_context_struct` of Linux. A
    /// context without a range takes the range of `def`. The context must be valid.
    pub fn string_to_context(&self, text: &str, def: Option<&Context>) -> Option<Context> {
        let (user, rest) = text.split_once(':')?;
        let (role, rest) = rest.split_once(':')?;
        let (ty, mls) = match rest.split_once(':') {
            Some((ty, mls)) => (ty, Some(mls)),
            None => (rest, None),
        };
        let mut c = Context {
            user: *self.names[sym::USERS].get(user)?,
            role: *self.names[sym::ROLES].get(role)?,
            ty: *self.names[sym::TYPES].get(ty)?,
            range: Range::default(),
        };
        match (self.mls, mls) {
            (false, Some(_)) => {
                def?;
            }
            (false, None) => {}
            (true, None) => c.range = def?.range.clone(),
            (true, Some(mls)) => c.range = self.parse_range(mls)?,
        }
        self.context_valid(&c).then_some(c)
    }

    /// Reads a range, as `mls_context_to_sid` of Linux. A range without a high level has the
    /// low level as its high level.
    pub fn parse_range(&self, text: &str) -> Option<Range> {
        let (low, high) = match text.split_once('-') {
            Some((low, high)) => (low, Some(high)),
            None => (text, None),
        };
        let low = self.parse_level(low)?;
        let high = match high {
            Some(high) => self.parse_level(high)?,
            None => low.clone(),
        };
        Some(Range { low, high })
    }

    fn parse_level(&self, text: &str) -> Option<Level> {
        let (sens, cats) = match text.split_once(':') {
            Some((sens, cats)) => (sens, Some(cats)),
            None => (text, None),
        };
        let sens = *self.names[sym::LEVELS].get(sens)?;
        let mut level = Level { sens, ..Level::default() };
        for cat in cats.into_iter().flat_map(|c| c.split(',')) {
            let (first, last) = match cat.split_once('.') {
                Some((first, last)) => (first, Some(last)),
                None => (cat, None),
            };
            let first = *self.names[sym::CATS].get(first)?;
            level.cats.set(first - 1, true);
            if let Some(last) = last {
                let last = *self.names[sym::CATS].get(last)?;
                if first >= last {
                    return None;
                }
                for bit in first..last {
                    level.cats.set(bit, true);
                }
            }
        }
        Some(level)
    }
}

#[cfg(test)]
mod tests {
    use crate::policydb::Policydb;

    fn policy() -> Policydb {
        Policydb::read(include_bytes!("../tests/rk_test.33.bin")).unwrap()
    }

    #[test]
    fn a_context_reads_and_writes_as_on_linux() {
        let p = policy();
        let text = |s: &str| p.string_to_context(s, None).map(|c| p.context_to_string(&c));
        let same = [
            "system_u:system_r:kernel_t:s0",
            "system_u:system_r:kernel_t:s0-s1:c0.c2",
            "system_u:object_r:etc_t:s1:c0,c2",
            "system_u:object_r:etc_t:s0:c1-s1:c0,c1",
        ];
        for s in same {
            assert_eq!(text(s).as_deref(), Some(s), "{s}");
        }
        assert_eq!(
            text("system_u:object_r:sbin_t:s0").as_deref(),
            Some("system_u:object_r:bin_t:s0")
        );
        assert_eq!(
            text("system_u:object_r:etc_t:s0-s0").as_deref(),
            Some("system_u:object_r:etc_t:s0")
        );
        assert_eq!(
            text("system_u:object_r:etc_t:s1a:c0,c1,cx").as_deref(),
            Some("system_u:object_r:etc_t:s1:c0.c2")
        );
        assert_eq!(
            text("system_u:object_r:etc_t:s1:c1.cx").as_deref(),
            Some("system_u:object_r:etc_t:s1:c1,c2")
        );
        let bad = [
            "system_u:object_r",
            "system_u:object_r:etc_t",
            "system_u:object_r:domain:s0",
            "system_u:object_r:nothing_t:s0",
            "system_u:object_r:etc_t:s2",
            "system_u:object_r:etc_t:s0:c2.c0",
            "system_u:object_r:etc_t:s1-s0",
            "system_u:object_r:etc_t:s0:c0.c1.c2",
            "system_u:user_r:etc_t:s0",
            "user_u:system_r:init_t:s0",
            "user_u:user_r:unconfined_t:s0-s1",
            "system_u:system_r:kernel_t:s0-s1:c0.c2:",
        ];
        for s in bad {
            assert_eq!(text(s), None, "{s}");
        }
        let def = p.string_to_context("system_u:object_r:etc_t:s1", None).unwrap();
        let c = p.string_to_context("system_u:object_r:bin_t", Some(&def)).unwrap();
        assert_eq!(p.context_to_string(&c), "system_u:object_r:bin_t:s1");
    }
}
