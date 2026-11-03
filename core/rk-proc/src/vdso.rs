//! The mapping of the vDSO in a new program, per spec/05-processes-signals-exec.md section 5.4.

use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::Once;
use rk_frame::vdso::{IMAGE, data_page};
use rk_mm::{AddressSpace, MmFile, MmapRequest, PAGE_SIZE, Prot, VmaKind};

use crate::timens::TimeNs;

/// The pages of the vDSO. All processes share them.
struct Pages(Vec<Arc<Frame>>);

impl MmFile for Pages {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        let index = usize::try_from(index).map_err(|_| Errno::EIO)?;
        self.0.get(index).cloned().ok_or(Errno::EIO)
    }
}

/// The pages of the vDSO and the data page. The first call makes them.
fn pages() -> Option<&'static (Arc<Pages>, Arc<Frame>)> {
    static PAGES: Once<Option<(Arc<Pages>, Arc<Frame>)>> = Once::new();
    PAGES
        .call_once(|| {
            let mut frames = Vec::new();
            for chunk in IMAGE.chunks(PAGE_SIZE) {
                let frame = alloc_zeroed_frame()?;
                frame.write_bytes(0, chunk);
                frames.push(Arc::new(frame));
            }
            Some((Arc::new(Pages(frames)), data_page()?))
        })
        .as_ref()
}

/// The two pages below the vDSO: the page of the offsets of the time namespace, and the data page
/// directly below the vDSO, as the `vvar` area of Linux.
fn vvar(ns: &TimeNs) -> Result<Arc<dyn MmFile>, Errno> {
    let (_, data) = pages().ok_or(Errno::ENOMEM)?;
    let offsets = ns.page().ok_or(Errno::ENOMEM)?;
    Ok(Arc::new(Pages(alloc::vec![offsets.clone(), data.clone()])))
}

/// The request that maps the `vvar` area of the time namespace `ns` at `addr`.
fn vvar_request(addr: usize, ns: &TimeNs) -> Result<MmapRequest, Errno> {
    Ok(MmapRequest {
        addr,
        fixed: true,
        may_write: false,
        file: Some((vvar(ns)?, 0)),
        kind: VmaKind::Vvar,
        ..MmapRequest::anon(VVAR_PAGES * PAGE_SIZE, Prot { read: true, write: false, exec: false })
    })
}

/// The pages of the `vvar` area.
const VVAR_PAGES: usize = 2;

/// Maps the `vvar` area of the time namespace `ns` and the vDSO directly above it, at an address
/// that `mmap` chooses. Gives the address of the vDSO, the value of `AT_SYSINFO_EHDR`, or 0 if
/// the architecture has no vDSO.
///
/// # Errors
///
/// Gives `ENOMEM` if no frame or no address range is free.
pub(crate) fn map(space: &AddressSpace, ns: &TimeNs) -> Result<usize, Errno> {
    if IMAGE.is_empty() {
        return Ok(0);
    }
    let (image, _) = pages().ok_or(Errno::ENOMEM)?;
    let len = image.0.len() * PAGE_SIZE;
    let read = Prot { read: true, write: false, exec: false };
    let base = space.mmap(MmapRequest::anon(VVAR_PAGES * PAGE_SIZE + len, read))?;
    space.mmap(vvar_request(base, ns)?)?;
    let file: Arc<dyn MmFile> = image.clone();
    space.mmap(MmapRequest {
        addr: base + VVAR_PAGES * PAGE_SIZE,
        fixed: true,
        file: Some((file, 0)),
        kind: VmaKind::Vdso,
        ..MmapRequest::anon(len, Prot { read: true, write: false, exec: true })
    })?;
    Ok(base + VVAR_PAGES * PAGE_SIZE)
}

/// Maps the page of the offsets of the time namespace `ns` in the `vvar` area of `space`, when
/// the process goes in `ns`, as `vdso_join_timens` of Linux. A space without all of the area,
/// after an `munmap` or an `mremap` of a part, does not change.
///
/// # Errors
///
/// Gives `ENOMEM` if no frame is free.
pub(crate) fn join_time_ns(space: &AddressSpace, ns: &TimeNs) -> Result<(), Errno> {
    let whole = space
        .areas()
        .into_iter()
        .find(|v| v.kind == VmaKind::Vvar && v.end - v.start == VVAR_PAGES * PAGE_SIZE);
    if let Some(v) = whole {
        space.mmap(vvar_request(v.start, ns)?)?;
    }
    Ok(())
}
