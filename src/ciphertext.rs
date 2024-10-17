use bulletproofs::{group::Group, BulletproofCurveArithmetic};
use core::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use elliptic_curve_tools::group_vec;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::{Error, Result};

/// A ciphertext that encodes a secret key share
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext<C: BulletproofCurveArithmetic> {
    #[serde(with = "group_vec")]
    pub c1: Vec<C::Point>,
    #[serde(with = "group_vec")]
    pub c2: Vec<C::Point>,
}

#[cfg(feature = "v1")]
impl<C: BulletproofCurveArithmetic> From<crate::v1::Ciphertext<C>> for Ciphertext<C> {
    fn from(value: crate::v1::Ciphertext<C>) -> Self {
        Self {
            c1: value.c1.to_vec(),
            c2: value.c2.to_vec(),
        }
    }
}

impl<C: BulletproofCurveArithmetic> Display for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXLOWER)
    }
}

impl<C: BulletproofCurveArithmetic> LowerHex for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: BulletproofCurveArithmetic> UpperHex for Ciphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXUPPER)
    }
}

impl<C: BulletproofCurveArithmetic> Hash for Ciphertext<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl<C: BulletproofCurveArithmetic> Ciphertext<C> {
    /// Return the byte representation of the ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * C::SCALAR_BYTES * C::POINT_BYTES);
        for point in self.c1.iter() {
            bytes.append(&mut C::serialize_point(point));
        }
        for point in self.c2.iter() {
            bytes.append(&mut C::serialize_point(point));
        }
        debug_assert_eq!(bytes.len(), 2 * C::SCALAR_BYTES * C::POINT_BYTES);
        bytes
    }

    /// Return the ciphertext represented by the given bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        assert_eq!(bytes.len(), 2 * C::SCALAR_BYTES * C::POINT_BYTES);

        let mut pos = bytes;
        let mut c1 = vec![C::Point::identity(); C::SCALAR_BYTES];
        for pt in c1.iter_mut() {
            *pt = C::deserialize_point(&pos[..C::POINT_BYTES])
                .map_err(|_| Error::DeserializedInvalidPoint)?;
            pos = &pos[C::POINT_BYTES..];
        }
        let mut c2 = vec![C::Point::identity(); C::SCALAR_BYTES];
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

#[test]
fn serialize_test() {
    use bulletproofs::p256::{NistP256, ProjectivePoint};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ciphertext = Ciphertext::<NistP256> {
        c1: vec![ProjectivePoint::GENERATOR; 32],
        c2: vec![ProjectivePoint::GENERATOR; 32],
    };

    let bytes = serde_bare::to_vec(&ciphertext).unwrap();
    let ciphertext2 = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(ciphertext, ciphertext2);

    let mut hasher = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    ciphertext.hash(&mut hasher);
    ciphertext2.hash(&mut hasher2);
    assert_eq!(hasher.finish(), hasher2.finish());
}
