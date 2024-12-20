use arbitrary::Unstructured;
use rand::RngCore;

/// Adapter from [`Unstructured`] to [`RngCore`] traits.
/// Uses defaults for rng traits.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RngUnstructured(pub Vec<u8>);
impl RngUnstructured {
    pub fn with_unstructured<R, F: FnOnce(&mut Unstructured<'_>) -> R>(&mut self, f: F) -> R {
        let mut u = Unstructured::new(self.0.as_slice());
        let start_len = u.len();
        let res = f(&mut u);
        let end_len = u.len();
        let delta = start_len - end_len;
        self.0.drain(..delta).for_each(drop);
        res
    }
    // `for<'a>` can be interpreted here as a null-lifetime, that is
    // the output doesn't borrow from the `Unstructured` which only exists inside the `with_unstructured` call
    pub fn arbitrary<A: for<'a> arbitrary::Arbitrary<'a> + 'static>(
        &mut self,
    ) -> arbitrary::Result<A> {
        self.with_unstructured(|u| u.arbitrary())
    }
}
impl RngUnstructured {
    /// Entropy left.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// No entropy left.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl From<&mut Unstructured<'_>> for RngUnstructured {
    fn from(value: &mut Unstructured<'_>) -> Self {
        Self(value.bytes(value.len()).unwrap().to_owned())
    }
}
impl From<Unstructured<'_>> for RngUnstructured {
    fn from(mut value: Unstructured<'_>) -> Self {
        Self(value.bytes(value.len()).unwrap().to_owned())
    }
}
impl RngCore for RngUnstructured {
    fn next_u32(&mut self) -> u32 {
        self.with_unstructured(|u| u.arbitrary().unwrap_or_default())
    }

    fn next_u64(&mut self) -> u64 {
        self.with_unstructured(|u| u.arbitrary().unwrap_or_default())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.with_unstructured(|u| {
            let bytes = u.bytes(u.len().min(dest.len())).unwrap();
            dest[..bytes.len()].copy_from_slice(bytes);
        })
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}
