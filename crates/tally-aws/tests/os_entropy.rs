//! Production OS entropy source contract. No AWS account or SDK calls.
use std::collections::HashSet;

use tally_aws::entropy::OsTokenSource;
use tally_core::authentication::SecureTokenSource;

#[test]
fn os_source_satisfies_the_portable_authentication_capability() {
    fn require_port<T: SecureTokenSource + Send + Sync>() {}
    require_port::<OsTokenSource>();
}

#[test]
fn os_source_produces_distinct_unpredictable_256_bit_credentials() {
    let source = OsTokenSource;
    let mut observed = HashSet::new();

    for _ in 0..32 {
        let secret = source.fresh_secret().expect("OS secure entropy available");
        assert_ne!(secret, [0u8; 32], "a zero credential is never acceptable");
        assert!(observed.insert(secret), "OS credentials must not repeat");
    }

    assert_eq!(observed.len(), 32);
}
