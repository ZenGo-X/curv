use std::{error, fmt};

/// Error type returned when conversion from hex to BigInt fails.
#[derive(Debug)]
pub struct ParseBigIntFromHexError {
    reason: ParseFromHexReason,
}

#[derive(Debug)]
pub enum ParseFromHexReason {
    #[cfg(feature = "rust-gmp-kzen")]
    Gmp(gmp::mpz::ParseMpzError),
    #[cfg(feature = "num-bigint")]
    Native,
}

impl fmt::Display for ParseBigIntFromHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            #[cfg(feature = "rust-gmp-kzen")]
            ParseFromHexReason::Gmp(reason) => write!(f, "{}", reason),
            #[cfg(feature = "num-bigint")]
            ParseFromHexReason::Native => write!(f, "invalid hex"),
        }
    }
}

impl error::Error for ParseBigIntFromHexError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.reason {
            #[cfg(feature = "rust-gmp-kzen")]
            ParseFromHexReason::Gmp(reason) => Some(reason),
            #[cfg(feature = "num-bigint")]
            ParseFromHexReason::Native => None,
        }
    }
}

impl From<ParseFromHexReason> for ParseBigIntFromHexError {
    fn from(reason: ParseFromHexReason) -> ParseBigIntFromHexError {
        ParseBigIntFromHexError { reason }
    }
}

/// Error type returned when conversion from BigInt to primitive integer type (u64, i64, etc) fails
#[derive(Debug)]
pub struct TryFromBigIntError {
    pub(super) type_name: &'static str,
}

impl fmt::Display for TryFromBigIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conversion from BigInt to {} overflowed", self.type_name)
    }
}

impl error::Error for TryFromBigIntError {}
