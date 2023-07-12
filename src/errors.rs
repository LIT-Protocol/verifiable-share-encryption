use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid point")]
    DeserializedInvalidPoint,
    #[error("invalid scalar")]
    DeserializedInvalidScalar,
    #[error("invalid dlog proof")]
    InvalidDlogProof,
    #[error("invalid range proof")]
    InvalidRangeProof,
    #[error("invalid segments proof")]
    InvalidSegmentsProof,
    #[error("invalid key")]
    InvalidKey,
}

pub type Result<T> = anyhow::Result<T, Error>;
