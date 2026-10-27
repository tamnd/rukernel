//! The mapping of the vDSO in a new program, per spec/05-processes-signals-exec.md section 5.4.

use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::Once;
use rk_frame::vdso::{IMAGE, data_page};
use rk_mm::{AddressSpace, MmFile, MmapRequest, PAGE_SIZE, Prot, VmaKind};

/// The pages of the vDSO or of its data page. All processes share them.
struct Pages(Vec<Arc<Frame>>);

impl MmFile for Pages {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        let index = usize::try_from(index).map_err(|_| Errno::EIO)?;
        self.0.get(index).cloned().ok_or(Errno::EIO)
    }
}

/// The pages of the vDSO and of the data page. The first call makes them.
fn pages() -> Option<&'static (Arc<Pages>, Arc<Pages>)> {
    static PAGES: Once<Option<(Arc<Pages>, Arc<Pages>)>> = Once::new();
    PAGES
        .call_once(|| {
            let mut frames = Vec::new();
            for chunk in IMAGE.chunks(PAGE_SIZE) {
                let frame = alloc_zeroed_frame()?;
                frame.write_bytes(0, chunk);
                frames.push(Arc::new(frame));
            }
            Some((Arc::new(Pages(frames)), Arc::new(Pages(alloc::vec![data_page()?]))))
        })
        .as_ref()
}

/// Maps the data page and the vDSO directly above it, at an address that `mmap` chooses. Gives
/// the address of the vDSO, the value of `AT_SYSINFO_EHDR`, or 0 if the architecture has no vDSO.
///
/// # Errors
///
/// Gives `ENOMEM` if no frame or no address range is free.
pub(crate) fn map(space: &AddressSpace) -> Result<usize, Errno> {
    if IMAGE.is_empty() {
        return Ok(0);
    }
    let (image, data) = pages().ok_or(Errno::ENOMEM)?;
    let len = image.0.len() * PAGE_SIZE;
    let read = Prot { read: true, write: false, exec: false };
    let base = space.mmap(MmapRequest::anon(PAGE_SIZE + len, read))?;
    let file: Arc<dyn MmFile> = data.clone();
    space.mmap(MmapRequest {
        addr: base,
        fixed: true,
        may_write: false,
        file: Some((file, 0)),
        kind: VmaKind::Vvar,
        ..MmapRequest::anon(PAGE_SIZE, read)
    })?;
    let file: Arc<dyn MmFile> = image.clone();
    space.mmap(MmapRequest {
        addr: base + PAGE_SIZE,
        fixed: true,
        file: Some((file, 0)),
        kind: VmaKind::Vdso,
        ..MmapRequest::anon(len, Prot { read: true, write: false, exec: true })
    })?;
    Ok(base + PAGE_SIZE)
}
