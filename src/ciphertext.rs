use bulletproofs::{group::Group, BulletproofCurveArithmetic};
use core::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use serde::{Deserialize, Serialize};

use crate::{errors::Result, serdes::PointArray, Error};

/// A ciphertext that encodes a secret key share
/// TODO: Use C::SCALAR_BYTES when #![feature(generic_const_exprs)] is stable
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext<C: BulletproofCurveArithmetic> {
    #[serde(with = "PointArray::<C>")]
    pub(crate) c1: [C::Point; 32],
    #[serde(with = "PointArray::<C>")]
    pub(crate) c2: [C::Point; 32],
}

impl<C: BulletproofCurveArithmetic> Display for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::BASE64)
    }
}

impl<C: BulletproofCurveArithmetic> LowerHex for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXLOWER)
    }
}

impl<C: BulletproofCurveArithmetic> UpperHex for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXUPPER)
    }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

    pub(crate) fn write_fmt(
        &self,
        f: &mut Formatter<'_>,
        encoding: data_encoding::Encoding,
    ) -> fmt::Result {
        write!(f, "Ciphertext {{ c1: [")?;
        for (i, pt) in self.c1.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            let bytes = C::serialize_point(pt);
            write!(f, "{}", encoding.encode(&bytes))?;
        }
        write!(f, "], c2: [")?;
        for (i, pt) in self.c2.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            let bytes = C::serialize_point(pt);
            write!(f, "{}", encoding.encode(&bytes))?;
        }
        write!(f, "] }}")
    }
}
