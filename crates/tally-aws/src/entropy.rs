//! Production source of unpredictable bearer credentials.
//!
//! The only responsibility of this adapter is to obtain 256 bits from the
//! operating system's cryptographically secure random source. Callers must
//! never derive bearer credentials from time, counters, UUIDs or web requests.

use tally_core::authentication::{AuthError, SecureTokenSource};

#[derive(Clone, Copy, Debug, Default)]
pub struct OsTokenSource;

impl SecureTokenSource for OsTokenSource {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).map_err(|_| AuthError::Entropy)?;
        Ok(token)
    }
}
