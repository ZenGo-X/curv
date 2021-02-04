use std::{error, fmt};

#[derive(Debug)]
pub struct ParseBigIntFromHexError {
    reason: ParseFromHexReason,
}

#[derive(Debug)]
pub enum ParseFromHexReason {
    Gmp(gmp::mpz::ParseMpzError),
}

impl fmt::Display for ParseBigIntFromHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            ParseFromHexReason::Gmp(reason) => write!(f, "{}", reason),
        }
    }
}

impl error::Error for ParseBigIntFromHexError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.reason {
            ParseFromHexReason::Gmp(reason) => Some(reason),
        }
    }
}

impl From<ParseFromHexReason> for ParseBigIntFromHexError {
    fn from(reason: ParseFromHexReason) -> ParseBigIntFromHexError {
        ParseBigIntFromHexError { reason }
    }
}

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
