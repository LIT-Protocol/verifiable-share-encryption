use bulletproofs::{
    group::ff::Field, merlin::Transcript, BulletproofCurveArithmetic, TranscriptProtocol,
};
use core::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use elliptic_curve_tools::{group, prime_field};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub(crate) struct DlogProofCommitting<C: BulletproofCurveArithmetic> {
    pub(crate) c1: C::Point,
    pub(crate) c2: C::Point,
    pub(crate) a1: C::Point,
    pub(crate) a2: C::Point,
    pub(crate) a3: C::Point,
    pub(crate) x: C::Scalar,
    pub(crate) r: C::Scalar,
    pub(crate) r1: C::Scalar,
    pub(crate) r2: C::Scalar,
}

impl<C: BulletproofCurveArithmetic> DlogProofCommitting<C> {
    pub fn finalize(self, challenge: C::Scalar) -> DlogProof<C> {
        DlogProof {
            c1: self.c1,
            c2: self.c2,
            a1: self.a1,
            a2: self.a2,
            a3: self.a3,
            message: self.r1 + challenge * self.x,
            blinding: self.r2 + challenge * self.r,
        }
    }
}

/// A schnorr proof of discrete log of a scalar value
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DlogProof<C: BulletproofCurveArithmetic> {
    #[serde(with = "group")]
    pub c1: C::Point,
    #[serde(with = "group")]
    pub c2: C::Point,
    #[serde(with = "group")]
    pub a1: C::Point,
    #[serde(with = "group")]
    pub a2: C::Point,
    #[serde(with = "group")]
    pub a3: C::Point,
    #[serde(with = "prime_field")]
    pub message: C::Scalar,
    #[serde(with = "prime_field")]
    pub blinding: C::Scalar,
}

#[cfg(feature = "v1")]
impl<C: BulletproofCurveArithmetic> From<crate::v1::DlogProof<C>> for DlogProof<C> {
    fn from(old: crate::v1::DlogProof<C>) -> Self {
        Self {
            c1: old.c1,
            c2: old.c2,
            a1: old.a1,
            a2: old.a2,
            a3: old.a3,
            message: old.message,
            blinding: old.blinding,
        }
    }
}

impl<C: BulletproofCurveArithmetic> Display for DlogProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXLOWER)
    }
}

impl<C: BulletproofCurveArithmetic> LowerHex for DlogProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: BulletproofCurveArithmetic> UpperHex for DlogProof<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.write_fmt(f, data_encoding::HEXUPPER)
    }
}

impl<C: BulletproofCurveArithmetic> DlogProof<C> {
    pub(crate) fn create(
        encryption_key: C::Point,
        key_share: &C::Scalar,
        r: &C::Scalar,
        generator: C::Point,
        transcript: &mut Transcript,
        mut rng: impl RngCore,
    ) -> DlogProofCommitting<C> {
        let pk_x = generator * key_share;

        let c1 = generator * r;
        let c2 = pk_x + encryption_key * r;

        let r1 = C::Scalar::random(&mut rng);
        let r2 = C::Scalar::random(&mut rng);

        let a1 = generator * r1;
        let a2 = encryption_key * r2;
        let a3 = generator * r2;

        transcript.append_point::<C>(b"G", &generator);
        transcript.append_point::<C>(b"Y", &encryption_key);
        transcript.append_point::<C>(b"C1", &c1);
        transcript.append_point::<C>(b"C2", &c2);
        transcript.append_point::<C>(b"Q", &pk_x);
        transcript.append_point::<C>(b"A1", &a1);
        transcript.append_point::<C>(b"A2", &a2);
        transcript.append_point::<C>(b"A3", &a3);

        DlogProofCommitting {
            c1,
            c2,
            a1,
            a2,
            a3,
            x: *key_share,
            r: *r,
            r1,
            r2,
        }
    }

    /// Return the byte representation of the DlogProof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(7 * C::POINT_BYTES + 2 * C::SCALAR_BYTES);
        bytes.append(&mut C::serialize_point(&self.c1));
        bytes.append(&mut C::serialize_point(&self.c2));
        bytes.append(&mut C::serialize_point(&self.a1));
        bytes.append(&mut C::serialize_point(&self.a2));
        bytes.append(&mut C::serialize_point(&self.a3));
        bytes.append(&mut C::serialize_scalar(&self.message));
        bytes.append(&mut C::serialize_scalar(&self.blinding));
        debug_assert_eq!(bytes.len(), 7 * C::POINT_BYTES + 2 * C::SCALAR_BYTES);
        bytes
    }

    /// Return the dlog proof represented by the given bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        assert_eq!(bytes.len(), 7 * C::POINT_BYTES + 2 * C::SCALAR_BYTES);
        let mut pos = bytes;
        macro_rules! read_point {
            () => {{
                let pt = C::deserialize_point(&pos[..C::POINT_BYTES])
                    .map_err(|_| Error::DeserializedInvalidPoint)?;
                pos = &pos[C::POINT_BYTES..];
                pt
            }};
        }
        macro_rules! read_scalar {
            () => {{
                let scalar = C::deserialize_scalar(&pos[..C::SCALAR_BYTES])
                    .map_err(|_| Error::DeserializedInvalidScalar)?;
                pos = &pos[C::SCALAR_BYTES..];
                scalar
            }};
        }

        let c1 = read_point!();
        let c2 = read_point!();
        let a1 = read_point!();
        let a2 = read_point!();
        let a3 = read_point!();
        let message = read_scalar!();
        let blinding = C::deserialize_scalar(&pos[..C::SCALAR_BYTES])
            .map_err(|_| Error::DeserializedInvalidScalar)?;
        Ok(Self {
            c1,
            c2,
            a1,
            a2,
            a3,
            message,
            blinding,
        })
    }

    pub(crate) fn write_fmt(
        &self,
        f: &mut Formatter<'_>,
        encoding: data_encoding::Encoding,
    ) -> fmt::Result {
        let c1 = C::serialize_point(&self.c1);
        let c2 = C::serialize_point(&self.c2);
        let a1 = C::serialize_point(&self.a1);
        let a2 = C::serialize_point(&self.a2);
        let a3 = C::serialize_point(&self.a3);
        let message = C::serialize_scalar(&self.message);
        let blinding = C::serialize_scalar(&self.blinding);
        write!(
            f,
            "DlogProof {{ c1: {}, c2: {}, a1: {}, a2: {}, a3: {}, message: {}, blinder: {} }}",
            encoding.encode(&c1),
            encoding.encode(&c2),
            encoding.encode(&a1),
            encoding.encode(&a2),
            encoding.encode(&a3),
            encoding.encode(&message),
            encoding.encode(&blinding)
        )
    }
}

#[test]
fn serialize_works() {
    use bulletproofs::k256::{ProjectivePoint, Scalar, Secp256k1};

    let dlog_proof = DlogProof::<Secp256k1> {
        c1: ProjectivePoint::GENERATOR,
        c2: ProjectivePoint::GENERATOR,
        a1: ProjectivePoint::GENERATOR,
        a2: ProjectivePoint::GENERATOR,
        a3: ProjectivePoint::GENERATOR,
        message: Scalar::ONE,
        blinding: Scalar::ONE,
    };

    let bytes = serde_bare::to_vec(&dlog_proof).unwrap();
    let dlog_proof2: DlogProof<Secp256k1> = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(dlog_proof, dlog_proof2);
}
