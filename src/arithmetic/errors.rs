use std::{error, fmt};

/// Error type returned when conversion from hex to BigInt fails.
#[derive(Debug)]
pub struct ParseBigIntError {
    pub(super) reason: ParseErrorReason,
    pub(super) radix: u8,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ParseErrorReason {
    #[cfg(feature = "rug")]
    Gmp(rug::integer::ParseIntegerError),
    #[cfg(feature = "num-bigint")]
    NumBigint,
}

impl fmt::Display for ParseBigIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            #[cfg(feature = "rug")]
            ParseErrorReason::Gmp(reason) => write!(f, "{}", reason),
            #[cfg(feature = "num-bigint")]
            ParseErrorReason::NumBigint => {
                write!(f, "invalid {}-based number representation", self.radix)
            }
        }
    }
}

impl error::Error for ParseBigIntError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.reason {
            #[cfg(feature = "rug")]
            ParseErrorReason::Gmp(reason) => Some(reason),
            #[cfg(feature = "num-bigint")]
            ParseErrorReason::NumBigint => None,
        }
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
