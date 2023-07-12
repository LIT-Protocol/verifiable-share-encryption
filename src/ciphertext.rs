use bulletproofs::{group::Group, BulletproofCurveArithmetic};
use serde::{Deserialize, Serialize};

use crate::{Error, errors::Result, serdes::PointArray};

/// A ciphertext that encodes a secret key share
/// TODO: Use C::SCALAR_BYTES when #![feature(generic_const_exprs)] is stable
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext<C: BulletproofCurveArithmetic> {
    #[serde(with = "PointArray::<C>")]
    pub(crate) c1: [C::Point; 32],
    #[serde(with = "PointArray::<C>")]
    pub(crate) c2: [C::Point; 32],
}

impl<C: BulletproofCurveArithmetic> Ciphertext<C> {
    /// Return the byte representation of the ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 * C::POINT_BYTES);
        for point in self.c1.iter() {
            bytes.append(&mut C::serialize_point(point));
        }
        for point in self.c2.iter() {
            bytes.append(&mut C::serialize_point(point));
        }
        debug_assert_eq!(bytes.len(), 64 * C::POINT_BYTES);
        bytes
    }

    /// Return the ciphertext represented by the given bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext<C>> {
        assert_eq!(bytes.len(), 64 * C::POINT_BYTES);

        let mut pos = bytes;
        let mut c1 = [C::Point::identity(); 32];
        for pt in c1.iter_mut() {
            *pt = C::deserialize_point(&pos[..C::POINT_BYTES])
                .map_err(|_| Error::DeserializedInvalidPoint)?;
            pos = &pos[C::POINT_BYTES..];
        }
        let mut c2 = [C::Point::identity(); 32];
        for pt in c2.iter_mut() {
            *pt = C::deserialize_point(&pos[..C::POINT_BYTES])
                .map_err(|_| Error::DeserializedInvalidPoint)?;
            pos = &pos[C::POINT_BYTES..];
        }
        Ok(Self { c1, c2 })
    }
}
