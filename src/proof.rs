use bulletproofs::{BulletproofCurveArithmetic, RangeProof};
use serde::{Deserialize, Serialize};

use crate::{ByteProof, DlogProof, serdes::CurveScalar};

/// The verifiable encryption proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<C: BulletproofCurveArithmetic> {
    #[serde(bound(serialize = "ByteProof<C>: Serialize"))]
    #[serde(bound(deserialize = "ByteProof<C>: Deserialize<'de>"))]
    pub(crate) byte_proofs: [ByteProof<C>; 32],
    #[serde(with = "CurveScalar::<C>")]
    pub(crate) challenge: C::Scalar,
    #[serde(bound(serialize = "DlogProof<C>: Serialize"))]
    #[serde(bound(deserialize = "DlogProof<C>: Deserialize<'de>"))]
    pub(crate) dlog_proof: DlogProof<C>,
    #[serde(bound(serialize = "RangeProof<C>: Serialize"))]
    #[serde(bound(deserialize = "RangeProof<C>: Deserialize<'de>"))]
    pub(crate) range_proof: RangeProof<C>,
}
