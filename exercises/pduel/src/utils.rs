use std::array::TryFromSliceError;


#[derive(Debug)]
pub enum CustomError {
    InvalidSignature,
    InvalidPublicKey,
    DecompressionError,
    Other(String)
}

impl From<TryFromSliceError> for CustomError {
    fn from(_value: TryFromSliceError) -> Self {
        Self::InvalidSignature
    }
}

