use bulletproofs::{BulletproofCurveArithmetic, RangeProof};
use serde::{Deserialize, Serialize};

use crate::{ByteProof, DlogProof};

/// The verifiable encryption proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<C: BulletproofCurveArithmetic> {
    pub(crate) byte_proofs: [ByteProof<C>; 32],
    pub(crate) challenge: C::Scalar,
    pub(crate) dlog_proof: DlogProof<C>,
    pub(crate) range_proof: RangeProof<C>,
}
