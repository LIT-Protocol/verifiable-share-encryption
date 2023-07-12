use bulletproofs::BulletproofCurveArithmetic;
use core::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use serde::{Deserialize, Serialize};

use crate::{errors::Result, serdes::CurveScalar, Error};

/// A schnorr proof of knowledge of a byte
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteProof<C: BulletproofCurveArithmetic> {
    #[serde(with = "CurveScalar::<C>")]
    pub(crate) message: C::Scalar,
    #[serde(with = "CurveScalar::<C>")]
    pub(crate) blinder: C::Scalar,
}

impl<C: BulletproofCurveArithmetic> Display for ByteProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::BASE64)
    }
}

impl<C: BulletproofCurveArithmetic> LowerHex for ByteProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXLOWER)
    }
}

impl<C: BulletproofCurveArithmetic> UpperHex for ByteProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXUPPER)
    }
}

impl<C: BulletproofCurveArithmetic> ByteProof<C> {
    /// Return the byte representation of the ByteProof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * C::SCALAR_BYTES);
        bytes.append(&mut C::serialize_scalar(&self.message));
        bytes.append(&mut C::serialize_scalar(&self.blinder));
        debug_assert_eq!(bytes.len(), 2 * C::SCALAR_BYTES);
        bytes
    }

    /// Return the byte proof represented by the given bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        assert_eq!(bytes.len(), 2 * C::SCALAR_BYTES);
        C::deserialize_scalar(&bytes[..C::SCALAR_BYTES])
            .and_then(|message| {
                C::deserialize_scalar(&bytes[C::SCALAR_BYTES..])
                    .map(|blinder| ByteProof { message, blinder })
            })
            .map_err(|_| Error::DeserializedInvalidScalar)
    }

    pub(crate) fn write_fmt(
        &self,
        f: &mut Formatter<'_>,
        encoding: data_encoding::Encoding,
    ) -> fmt::Result {
        let message = C::serialize_scalar(&self.message);
        let blinder = C::serialize_scalar(&self.blinder);
        write!(
            f,
            "ByteProof {{ message: {}, blinder: {} }}",
            encoding.encode(&message),
            encoding.encode(&blinder)
        )
    }
}
