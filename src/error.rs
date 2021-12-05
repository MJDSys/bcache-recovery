use std::fmt::{Display, Formatter};
use std::io;
use std::num::TryFromIntError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BCacheRecoveryError {
    #[error("IO Error {0}")]
    IoError(#[from] io::Error),
    #[error("Response parse error {0}")]
    ParseError(nom::Err<nom::error::Error<Vec<u8>>>),
    #[error("Failed to get enough information")]
    ShortRead,
    #[error("Unrecoverable BCache error {0}")]
    BCacheError(BCacheErrorKind),
    #[error("Unsupported feature {0}")]
    UnsupportedFeature(UnsupportedFeatureKind),
    #[error("Integer conversion issue (small platform) {0}")]
    IntegerConversionError(#[from] TryFromIntError),
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for BCacheRecoveryError {
    fn from(original_error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        match original_error {
            nom::Err::Failure(e) | nom::Err::Error(e) => Self::ParseError(nom::Err::Failure(
                nom::error::Error::new(Vec::from(e.input), e.code),
            )),
            nom::Err::Incomplete(_) => Self::ShortRead,
        }
    }
}

#[derive(Debug)]
pub enum BCacheErrorKind {
    UnsupportedVersion(u64),
    BadOffset(u64),
    BadMagic([u8; 16]),
    BadSetMagic(u64),
    BadChecksum(u64, u64),
    BadUuid([u8; 16]),
    BadBtreeKey(crate::BKey),
    BadBtree(crate::BKey),
}

impl Display for BCacheErrorKind {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub enum UnsupportedFeatureKind {
    NonSynchronousCache,
}

impl Display for UnsupportedFeatureKind {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

pub(crate) type Result<T> = std::result::Result<T, BCacheRecoveryError>;
