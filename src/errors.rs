use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid point")]
    DeserializedInvalidPoint,
    #[error("invalid scalar")]
    DeserializedInvalidScalar,
}

pub type Result<T> = anyhow::Result<T, Error>;
