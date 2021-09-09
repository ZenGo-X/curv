use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use digest::Digest;

/// Zero-sized marker type denoting choice of hash function
pub struct HashChoice<H: Digest + Clone>(PhantomData<fn(H)>);

impl<H: Digest + Clone> Default for HashChoice<H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<H: Digest + Clone> HashChoice<H> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H: Digest + Clone> Clone for HashChoice<H> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<H: Digest + Clone> fmt::Debug for HashChoice<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashChoice<_>")
    }
}

impl<H: Digest + Clone> PartialEq for HashChoice<H> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<H: Digest + Clone> Eq for HashChoice<H> {}

impl<H: Digest + Clone> PartialOrd for HashChoice<H> {
    fn partial_cmp(&self, _other: &Self) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl<H: Digest + Clone> Ord for HashChoice<H> {
    fn cmp(&self, _other: &Self) -> Ordering {
        Ordering::Equal
    }
}

impl<H: Digest + Clone> Hash for HashChoice<H> {
    fn hash<N: Hasher>(&self, _state: &mut N) {}
}
