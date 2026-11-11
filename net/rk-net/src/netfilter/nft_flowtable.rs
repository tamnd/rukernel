//! The flowtables of nf_tables, as the flowtables of nf_tables_api.c and nft_flow_offload.c of
//! Linux.
//!
//! A flowtable has a hook on the ingress of a list of devices. The expression `flow_offload`
//! of a rule in the forward hook puts a connection in a flowtable. Here a flowtable keeps its
//! devices, its priority and its flags for the dumps, and `flow_offload` does not change the
//! path of the packets: they go through the hooks as before.
//!
//! A device that goes away leaves the flowtable, as the `NETDEV_UNREGISTER` event of Linux
//! does. The flowtable keeps a weak reference to each device, and a device that is not in the
//! namespace any more is not in the dumps or the checks.

use super::super::{
    NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NFT, NFT_MSG_DELFLOWTABLE, NFT_MSG_DESTROYFLOWTABLE,
    NFT_MSG_NEWFLOWTABLE, NftBatch, NftCtx, NftTable, bad, be32, be64, cstr, family_match,
    nfnl_msg_put, nft_table_lookup, nft_type, nla_name,
};
use super::{NftExpr, nla_raw};
use crate::consts::IFNAMSIZ;
use crate::dev::NetDevice;
use crate::netlink::msg::Attrs;
use crate::netlink::nfnetlink::{NFNETLINK_V0, NfnlInfo};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_TYPE_MASK, NLM_F_EXCL, NLM_F_MULTI};
use rk_vfs::inode::Result;

// The attributes of a flowtable, `enum nft_flowtable_attributes`.
const NFTA_FLOWTABLE_TABLE: u32 = 1;
const NFTA_FLOWTABLE_NAME: u32 = 2;
const NFTA_FLOWTABLE_HOOK: u32 = 3;
const NFTA_FLOWTABLE_USE: u32 = 4;
const NFTA_FLOWTABLE_HANDLE: u32 = 5;
const NFTA_FLOWTABLE_FLAGS: u32 = 7;
/// The last attribute of a flowtable, `NFTA_FLOWTABLE_MAX`.
pub(in super::super) const NFTA_FLOWTABLE_MAX: u16 = 7;

// The attributes of the hook of a flowtable, `enum nft_flowtable_hook_attributes`.
const NFTA_FLOWTABLE_HOOK_NUM: u32 = 1;
const NFTA_FLOWTABLE_HOOK_PRIORITY: u32 = 2;
const NFTA_FLOWTABLE_HOOK_DEVS: u32 = 3;

/// A device in a list of devices, `NFTA_DEVICE_NAME`.
const NFTA_DEVICE_NAME: u32 = 1;

/// The flags of a flowtable, `NFT_FLOWTABLE_HW_OFFLOAD` and `NFT_FLOWTABLE_COUNTER`.
const NFT_FLOWTABLE_HW_OFFLOAD: u32 = 1;
const NFT_FLOWTABLE_MASK: u32 = 3;

/// The only hook of a flowtable, `NF_NETDEV_INGRESS`.
const NF_NETDEV_INGRESS: u32 = 0;

/// The most devices in a list, `NFT_NETDEVICE_MAX`.
const NFT_NETDEVICE_MAX: usize = 256;

/// The attribute of `flow_offload`, `NFTA_FLOW_TABLE_NAME`.
const NFTA_FLOW_TABLE_NAME: u32 = 1;

/// A flowtable of a table, as `struct nft_flowtable` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftFlowtable {
    pub(crate) name: Vec<u8>,
    pub(crate) handle: u64,
    hooknum: u32,
    priority: i32,
    flags: u32,
    /// The devices, as the `hook_list` of Linux.
    devs: Vec<Weak<NetDevice>>,
}

/// Gives the device if it is still in the namespace.
fn nft_dev_live(w: &Weak<NetDevice>) -> Option<Arc<NetDevice>> {
    let d = w.upgrade()?;
    let now = crate::dev::by_index(d.ifindex())?;
    Arc::ptr_eq(&d, &now).then_some(d)
}

/// Tells if the list `devs` has the device `d`, as `nft_hook_list_find` of Linux.
fn nft_dev_find(devs: &[Weak<NetDevice>], d: &Arc<NetDevice>) -> Option<usize> {
    devs.iter().position(|w| nft_dev_live(w).is_some_and(|x| Arc::ptr_eq(&x, d)))
}

impl NftFlowtable {
    /// The devices that are still in the namespace.
    fn live_devs(&self) -> Vec<Arc<NetDevice>> {
        self.devs.iter().filter_map(nft_dev_live).collect()
    }
}

impl NftTable {
    /// The number of rules that use the flowtable `handle`, as `flowtable->use` of Linux.
    pub(crate) fn flowtable_use(&self, handle: u64) -> u32 {
        self.chains
            .iter()
            .flat_map(|c| c.rules.iter())
            .flat_map(|r| r.parsed.iter())
            .filter(|e| matches!(e, NftExpr::FlowOffload { flowtable } if *flowtable == handle))
            .count() as u32
    }
}

/// Finds the flowtable `name`, as `nft_flowtable_lookup` of Linux.
fn nft_flowtable_lookup(table: &NftTable, name: Option<&[u8]>) -> Result<usize> {
    let Some(name) = name else { return Err(Errno::EINVAL) };
    table.flowtables.iter().position(|f| f.name == name).ok_or(Errno::ENOENT)
}

/// Reads the list of devices `NFTA_FLOWTABLE_HOOK_DEVS`, as `nf_tables_parse_netdev_hooks` of
/// Linux.
fn nft_parse_devs(data: &[u8]) -> Result<Vec<Arc<NetDevice>>> {
    let mut devs: Vec<Arc<NetDevice>> = Vec::new();
    for (ty, v) in nla_raw(data) {
        if u32::from(ty & NLA_TYPE_MASK as u16) != NFTA_DEVICE_NAME {
            return Err(Errno::EINVAL);
        }
        let len = if v.last() == Some(&0) { v.len() - 1 } else { v.len() };
        if len > IFNAMSIZ - 1 {
            return Err(Errno::ERANGE);
        }
        let name = v.split(|&c| c == 0).next().unwrap_or(v);
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        let d = crate::dev::by_name(name).ok_or(Errno::ENOENT)?;
        if devs.iter().any(|x| Arc::ptr_eq(x, &d)) {
            return Err(Errno::EEXIST);
        }
        devs.push(d);
        if devs.len() == NFT_NETDEVICE_MAX {
            return Err(Errno::EFBIG);
        }
    }
    Ok(devs)
}

/// The hook of a flowtable: the hook number, the priority and the devices.
struct NftFlowtableHook {
    num: u32,
    priority: i32,
    devs: Vec<Arc<NetDevice>>,
}

/// Reads `NFTA_FLOWTABLE_HOOK`, as `nft_flowtable_parse_hook` of Linux. A new flowtable needs
/// the hook number and the priority. A change must give the same ones or none.
fn nft_flowtable_parse_hook(data: &[u8], ft: Option<&NftFlowtable>) -> Result<NftFlowtableHook> {
    let a = Attrs::parse(data, 3);
    let num = be32(&a, NFTA_FLOWTABLE_HOOK_NUM)?;
    let priority = be32(&a, NFTA_FLOWTABLE_HOOK_PRIORITY)?.map(|p| p as i32);
    let (num, priority) = match ft {
        None => {
            let (Some(num), Some(priority)) = (num, priority) else {
                return Err(Errno::ENOENT);
            };
            if num != NF_NETDEV_INGRESS {
                return Err(Errno::EOPNOTSUPP);
            }
            (num, priority)
        }
        Some(ft) => {
            if num.is_some_and(|n| n != ft.hooknum) || priority.is_some_and(|p| p != ft.priority) {
                return Err(Errno::EOPNOTSUPP);
            }
            (ft.hooknum, ft.priority)
        }
    };
    let devs = match a.get(NFTA_FLOWTABLE_HOOK_DEVS) {
        Some(d) => nft_parse_devs(d)?,
        None => Vec::new(),
    };
    Ok(NftFlowtableHook { num, priority, devs })
}

/// The message of a flowtable, as `nf_tables_fill_flowtable_info` of Linux. `devs` are the
/// devices of the message, or all the devices of the flowtable. The notice of a removed
/// flowtable has only its name and its handle.
#[allow(clippy::too_many_arguments)]
fn nf_tables_fill_flowtable_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    ft: &NftFlowtable,
    devs: Option<&[Arc<NetDevice>]>,
) -> Vec<u8> {
    let mut b = nfnl_msg_put(
        portid,
        seq,
        nft_type(event),
        flags,
        table.family,
        NFNETLINK_V0,
        base_seq as u16,
    );
    b.put(NFTA_FLOWTABLE_TABLE as u16, &cstr(&table.name))
        .put(NFTA_FLOWTABLE_NAME as u16, &cstr(&ft.name))
        .put(NFTA_FLOWTABLE_HANDLE as u16, &ft.handle.to_be_bytes());
    if devs.is_none() && (event == NFT_MSG_DELFLOWTABLE || event == NFT_MSG_DESTROYFLOWTABLE) {
        return b.finish();
    }
    b.put(NFTA_FLOWTABLE_USE as u16, &table.flowtable_use(ft.handle).to_be_bytes())
        .put(NFTA_FLOWTABLE_FLAGS as u16, &ft.flags.to_be_bytes());
    let hook = b.nest(NFTA_FLOWTABLE_HOOK as u16);
    b.put(NFTA_FLOWTABLE_HOOK_NUM as u16, &ft.hooknum.to_be_bytes())
        .put(NFTA_FLOWTABLE_HOOK_PRIORITY as u16, &ft.priority.to_be_bytes());
    let nest = b.nest(NFTA_FLOWTABLE_HOOK_DEVS as u16);
    let all;
    let devs: &[Arc<NetDevice>] = match devs {
        Some(d) => d,
        None => {
            all = ft.live_devs();
            &all
        }
    };
    for d in devs {
        b.put(NFTA_DEVICE_NAME as u16, &cstr(d.name().as_bytes()));
    }
    b.end_nest(nest);
    b.end_nest(hook);
    b.finish()
}

/// Gets one flowtable, as `nf_tables_getflowtable` of Linux.
pub(in super::super) fn nf_tables_getflowtable(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let Some(name) = nla_name(nla, NFTA_FLOWTABLE_NAME)? else { return Err(Errno::EINVAL) };
    let family = info.nfmsg.nfgen_family;
    let nft = NFT.lock();
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_FLOWTABLE_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_FLOWTABLE_TABLE, e))?;
    let table = &nft.tables[t];
    let f = nft_flowtable_lookup(table, Some(name))
        .map_err(|e| bad(info, nla, NFTA_FLOWTABLE_NAME, e))?;
    let m = nf_tables_fill_flowtable_info(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWFLOWTABLE,
        0,
        nft.base_seq,
        table,
        &table.flowtables[f],
        None,
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

/// The dump of the flowtables, as `nf_tables_dump_flowtable` of Linux. `NFTA_FLOWTABLE_TABLE`
/// limits the dump to one table.
pub(in super::super) fn nf_tables_dump_flowtable(
    info: &NfnlInfo<'_>,
    nla: &Attrs<'_>,
) -> Result<Vec<Vec<u8>>> {
    let table_name = nla_name(nla, NFTA_FLOWTABLE_TABLE)?;
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let mut out = Vec::new();
    for t in nft.tables.iter().filter(|t| family_match(family, t)) {
        if table_name.is_some_and(|n| n != t.name) {
            continue;
        }
        for f in &t.flowtables {
            out.push(nf_tables_fill_flowtable_info(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWFLOWTABLE,
                NLM_F_MULTI as u16,
                nft.base_seq,
                t,
                f,
                None,
            ));
        }
    }
    Ok(out)
}

/// Reads a `flow_offload` expression, as `nft_flow_offload_init` of Linux. Only the tables of
/// the families ip, ip6 and inet can have it, as `nft_flow_offload_validate`.
pub(super) fn nft_flow_offload_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    let a = Attrs::parse(data, 1);
    let Some(name) = nla_name(&a, NFTA_FLOW_TABLE_NAME)? else { return Err(Errno::EINVAL) };
    let f = nft_flowtable_lookup(table, Some(name))?;
    if !matches!(table.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(NftExpr::FlowOffload { flowtable: table.flowtables[f].handle })
}

impl NftBatch {
    /// The notice of a flowtable, as `nf_tables_flowtable_notify` of Linux.
    fn notify_flowtable(
        &mut self,
        ctx: &NftCtx,
        event: u8,
        t: usize,
        f: usize,
        devs: Option<&[Arc<NetDevice>]>,
    ) {
        let flags = ctx.notify_flags();
        let m = self.want(ctx).then(|| {
            let table = &self.tables[t];
            nf_tables_fill_flowtable_info(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                table,
                &table.flowtables[f],
                devs,
            )
        });
        self.notify(ctx, m);
    }

    /// Removes the flowtable `f` with a notice, for the flush of a table.
    pub(in super::super) fn nft_delflowtable(&mut self, ctx: &NftCtx, t: usize, f: usize) {
        self.notify_flowtable(ctx, NFT_MSG_DELFLOWTABLE, t, f, None);
        self.tables[t].flowtables.remove(f);
    }

    /// Makes a flowtable, or adds devices to a flowtable, as `nf_tables_newflowtable` of
    /// Linux.
    pub(in super::super) fn nf_tables_newflowtable(
        &mut self,
        info: &NfnlInfo<'_>,
        nla: &Attrs<'_>,
    ) -> Result<()> {
        let ctx = NftCtx::new(info);
        let (Some(_), Some(name), Some(hook)) = (
            nla.get(NFTA_FLOWTABLE_TABLE),
            nla_name(nla, NFTA_FLOWTABLE_NAME)?,
            nla.get(NFTA_FLOWTABLE_HOOK),
        ) else {
            return Err(Errno::EINVAL);
        };
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_FLOWTABLE_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_FLOWTABLE_TABLE, e))?;
        let flags = be32(nla, NFTA_FLOWTABLE_FLAGS)?;
        if flags.is_some_and(|f| f & !NFT_FLOWTABLE_MASK != 0) {
            return Err(Errno::EOPNOTSUPP);
        }
        if let Ok(f) = nft_flowtable_lookup(&self.tables[t], Some(name)) {
            if ctx.has(NLM_F_EXCL) {
                return Err(bad(info, nla, NFTA_FLOWTABLE_NAME, Errno::EEXIST));
            }
            return self.nft_flowtable_update(&ctx, t, f, flags, hook);
        }
        if !matches!(ctx.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
            return Err(Errno::ENOENT);
        }
        let h = nft_flowtable_parse_hook(hook, None).map_err(|e| {
            if e == Errno::ENOENT { bad(info, nla, NFTA_FLOWTABLE_NAME, e) } else { e }
        })?;
        // A device can be in only one flowtable of a table, as
        // `nft_register_flowtable_net_hooks` of Linux.
        let table = &self.tables[t];
        if h.devs
            .iter()
            .any(|d| table.flowtables.iter().any(|f| nft_dev_find(&f.devs, d).is_some()))
        {
            return Err(Errno::EEXIST);
        }
        let table = &mut self.tables[t];
        let handle = table.alloc_handle();
        table.flowtables.push(NftFlowtable {
            name: name.to_vec(),
            handle,
            hooknum: h.num,
            priority: h.priority,
            flags: flags.unwrap_or(0),
            devs: h.devs.iter().map(Arc::downgrade).collect(),
        });
        let f = table.flowtables.len() - 1;
        self.notify_flowtable(&ctx, NFT_MSG_NEWFLOWTABLE, t, f, None);
        Ok(())
    }

    /// Adds devices to the flowtable `f`, and changes its flags, as `nft_flowtable_update` of
    /// Linux. The flag `NFT_FLOWTABLE_HW_OFFLOAD` cannot change. The notice has only the new
    /// devices.
    fn nft_flowtable_update(
        &mut self,
        ctx: &NftCtx,
        t: usize,
        f: usize,
        flags: Option<u32>,
        hook: &[u8],
    ) -> Result<()> {
        let ft = &self.tables[t].flowtables[f];
        let flags = match flags {
            Some(fl) if (fl ^ ft.flags) & NFT_FLOWTABLE_HW_OFFLOAD != 0 => {
                return Err(Errno::EOPNOTSUPP);
            }
            Some(fl) => fl,
            None => ft.flags,
        };
        let mut h = nft_flowtable_parse_hook(hook, Some(ft))?;
        h.devs.retain(|d| nft_dev_find(&ft.devs, d).is_none());
        let ft = &mut self.tables[t].flowtables[f];
        ft.flags = flags;
        ft.devs.retain(|w| nft_dev_live(w).is_some());
        // The new devices go at the front of the list, as `list_splice_rcu` of Linux.
        let mut devs: Vec<Weak<NetDevice>> = h.devs.iter().map(Arc::downgrade).collect();
        devs.append(&mut ft.devs);
        ft.devs = devs;
        self.notify_flowtable(ctx, NFT_MSG_NEWFLOWTABLE, t, f, Some(&h.devs[..]));
        Ok(())
    }

    /// Removes a flowtable by its name or its handle, as `nf_tables_delflowtable` of Linux.
    /// With `NFTA_FLOWTABLE_HOOK`, it removes only the devices of the hook from the flowtable.
    /// A flowtable that a rule uses gives `EBUSY`.
    pub(in super::super) fn nf_tables_delflowtable(
        &mut self,
        info: &NfnlInfo<'_>,
        nla: &Attrs<'_>,
    ) -> Result<()> {
        let ctx = NftCtx::new(info);
        let name = nla_name(nla, NFTA_FLOWTABLE_NAME)?;
        let handle = be64(nla, NFTA_FLOWTABLE_HANDLE)?;
        if !nla.has(NFTA_FLOWTABLE_TABLE) || (name.is_none() && handle.is_none()) {
            return Err(Errno::EINVAL);
        }
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_FLOWTABLE_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_FLOWTABLE_TABLE, e))?;
        let table = &self.tables[t];
        let (r, attr) = match handle {
            Some(h) => (
                table.flowtables.iter().position(|f| f.handle == h).ok_or(Errno::ENOENT),
                NFTA_FLOWTABLE_HANDLE,
            ),
            None => (nft_flowtable_lookup(table, name), NFTA_FLOWTABLE_NAME),
        };
        let f = match r {
            Ok(f) => f,
            Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYFLOWTABLE => return Ok(()),
            Err(e) => return Err(bad(info, nla, attr, e)),
        };
        if let Some(hook) = nla.get(NFTA_FLOWTABLE_HOOK) {
            // As `nft_delflowtable_hook` of Linux.
            let ft = &table.flowtables[f];
            let h = nft_flowtable_parse_hook(hook, Some(ft))?;
            let mut gone = Vec::new();
            for d in &h.devs {
                gone.push(nft_dev_find(&ft.devs, d).ok_or(Errno::ENOENT)?);
            }
            self.notify_flowtable(&ctx, ctx.ty, t, f, Some(&h.devs[..]));
            gone.sort_unstable();
            let ft = &mut self.tables[t].flowtables[f];
            for i in gone.into_iter().rev() {
                ft.devs.remove(i);
            }
            return Ok(());
        }
        if table.flowtable_use(table.flowtables[f].handle) > 0 {
            return Err(bad(info, nla, attr, Errno::EBUSY));
        }
        self.nft_delflowtable(&ctx, t, f);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::msg::Builder;

    fn attr(ty: u32, v: &[u8]) -> Vec<u8> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(ty as u16, v);
        b.finish()[crate::netlink::msg::HDRLEN..].to_vec()
    }

    fn flowtable(hooknum: u32, priority: i32) -> NftFlowtable {
        NftFlowtable {
            name: b"f".to_vec(),
            handle: 1,
            hooknum,
            priority,
            flags: 0,
            devs: Vec::new(),
        }
    }

    #[test]
    fn a_new_flowtable_needs_the_ingress_hook_and_a_priority() {
        let mut d = attr(NFTA_FLOWTABLE_HOOK_NUM, &0u32.to_be_bytes());
        assert_eq!(nft_flowtable_parse_hook(&d, None).err(), Some(Errno::ENOENT));
        d.extend(attr(NFTA_FLOWTABLE_HOOK_PRIORITY, &(-10i32).to_be_bytes()));
        let h = nft_flowtable_parse_hook(&d, None).unwrap();
        assert_eq!((h.num, h.priority, h.devs.len()), (0, -10, 0));
        let mut d = attr(NFTA_FLOWTABLE_HOOK_NUM, &1u32.to_be_bytes());
        d.extend(attr(NFTA_FLOWTABLE_HOOK_PRIORITY, &0u32.to_be_bytes()));
        assert_eq!(nft_flowtable_parse_hook(&d, None).err(), Some(Errno::EOPNOTSUPP));
    }

    #[test]
    fn a_change_keeps_the_hook_and_the_priority() {
        let ft = flowtable(0, 10);
        let h = nft_flowtable_parse_hook(&[], Some(&ft)).unwrap();
        assert_eq!((h.num, h.priority), (0, 10));
        let d = attr(NFTA_FLOWTABLE_HOOK_PRIORITY, &11u32.to_be_bytes());
        assert_eq!(nft_flowtable_parse_hook(&d, Some(&ft)).err(), Some(Errno::EOPNOTSUPP));
        let d = attr(NFTA_FLOWTABLE_HOOK_PRIORITY, &10u32.to_be_bytes());
        assert!(nft_flowtable_parse_hook(&d, Some(&ft)).is_ok());
    }

    #[test]
    fn a_list_of_devices_has_only_device_names() {
        assert_eq!(nft_parse_devs(&attr(2, b"lo\0")).err(), Some(Errno::EINVAL));
        let long = [b'a'; IFNAMSIZ];
        assert_eq!(nft_parse_devs(&attr(NFTA_DEVICE_NAME, &long)).err(), Some(Errno::ERANGE));
        assert_eq!(nft_parse_devs(&[]).unwrap().len(), 0);
    }
}
