use bulletproofs::{BulletproofCurveArithmetic, RangeProof};
use elliptic_curve_tools::prime_field;
use serde::{Deserialize, Serialize};

use crate::{ByteProof, DlogProof};

/// The verifiable encryption proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<C: BulletproofCurveArithmetic> {
    #[serde(bound(serialize = "ByteProof<C>: Serialize"))]
    #[serde(bound(deserialize = "ByteProof<C>: Deserialize<'de>"))]
    pub byte_proofs: Vec<ByteProof<C>>,
    #[serde(with = "prime_field")]
    pub challenge: C::Scalar,
    #[serde(bound(serialize = "DlogProof<C>: Serialize"))]
    #[serde(bound(deserialize = "DlogProof<C>: Deserialize<'de>"))]
    pub dlog_proof: DlogProof<C>,
    #[serde(bound(serialize = "RangeProof<C>: Serialize"))]
    #[serde(bound(deserialize = "RangeProof<C>: Deserialize<'de>"))]
    pub range_proof: RangeProof<C>,
}

#[cfg(feature = "v1")]
impl<C: BulletproofCurveArithmetic> From<crate::v1::Proof<C>> for Proof<C> {
    fn from(old: crate::v1::Proof<C>) -> Self {
        Self {
            byte_proofs: old.byte_proofs.into_iter().map(ByteProof::from).collect(),
            challenge: old.challenge,
            dlog_proof: DlogProof::from(old.dlog_proof),
            range_proof: old.range_proof,
        }
    }
}
