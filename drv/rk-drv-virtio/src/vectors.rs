//! The MSI-X vectors of a virtio device on the PCI bus, as `vp_find_vqs` and `vp_find_vqs_msix` of
//! Linux in drivers/virtio/virtio_pci_common.c. The driver tries the modes in the order of
//! `modes`: first a vector for the configuration and a vector for each queue, then one vector
//! that the configuration and all queues share. If the function cannot get the vectors of a mode,
//! or the device does not take them, the driver tries the next mode, and then the INTx pin.

/// The value of an MSI-X vector register for no vector.
pub(crate) const NO_VECTOR: u16 = 0xffff;

/// A way to give the MSI-X vectors to the configuration and to the queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Vector 0 for the configuration, and vector `1 + n` for the queue `n`.
    PerQueue,
    /// Vector 0 for the configuration and for all queues.
    Shared,
}

impl Mode {
    /// The number of vectors of the mode for `queues` queues.
    pub(crate) fn count(self, queues: u16) -> usize {
        match self {
            Self::PerQueue => usize::from(queues) + 1,
            Self::Shared => 1,
        }
    }

    /// The vector of the configuration.
    pub(crate) fn config_vector(self) -> u16 {
        0
    }

    /// The vector of the queue `index` of `queues` queues, or `NO_VECTOR` for a queue that the
    /// driver did not tell, which the driver then polls.
    pub(crate) fn queue_vector(self, index: u16, queues: u16) -> u16 {
        match self {
            _ if index >= queues => NO_VECTOR,
            Self::PerQueue => index + 1,
            Self::Shared => 0,
        }
    }

    /// The index of the line of the queue `index` in the lines of the mode, as `queue_vector`.
    pub(crate) fn queue_line(self, index: u16, queues: u16) -> Option<usize> {
        match self.queue_vector(index, queues) {
            NO_VECTOR => None,
            v => Some(usize::from(v)),
        }
    }
}

/// The modes to try, in order, for `queues` queues on a function with an MSI-X table of
/// `table_size` entries. A mode with more vectors than the table has is not tried. With one
/// queue, a vector for each queue is two vectors, so it comes before the shared vector also then.
pub(crate) fn modes(queues: u16, table_size: usize) -> impl Iterator<Item = Mode> {
    [Mode::PerQueue, Mode::Shared].into_iter().filter(move |m| m.count(queues) <= table_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn per_queue_gives_vector_zero_to_the_configuration() {
        let m = Mode::PerQueue;
        assert_eq!(m.count(2), 3);
        assert_eq!(m.config_vector(), 0);
        assert_eq!(m.queue_vector(0, 2), 1);
        assert_eq!(m.queue_vector(1, 2), 2);
        assert_eq!(m.queue_vector(2, 2), NO_VECTOR);
        assert_eq!(m.queue_line(1, 2), Some(2));
        assert_eq!(m.queue_line(5, 2), None);
    }

    #[test]
    fn shared_gives_one_vector_to_all() {
        let m = Mode::Shared;
        assert_eq!(m.count(3), 1);
        assert_eq!(m.config_vector(), 0);
        assert!((0..3).all(|q| m.queue_vector(q, 3) == 0 && m.queue_line(q, 3) == Some(0)));
        assert_eq!(m.queue_vector(3, 3), NO_VECTOR);
    }

    #[test]
    fn modes_fall_back_when_the_table_is_small() {
        let all = |queues, size| modes(queues, size).collect::<Vec<_>>();
        assert_eq!(all(2, 3), [Mode::PerQueue, Mode::Shared]);
        assert_eq!(all(2, 64), [Mode::PerQueue, Mode::Shared]);
        assert_eq!(all(2, 2), [Mode::Shared]);
        assert_eq!(all(1, 2), [Mode::PerQueue, Mode::Shared]);
        assert_eq!(all(1, 1), [Mode::Shared]);
        // No MSI-X table: the driver uses the INTx pin.
        assert!(all(2, 0).is_empty());
    }
}
