use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid point")]
    DeserializedInvalidPoint,
}

pub type Result<T> = anyhow::Result<T, Error>;