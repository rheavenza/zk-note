//! Protocol types, constants, error codes, and serialization models
//! for the zero-knowledge notes system.

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-protocol"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_init() {
        assert_eq!(crate_name(), "zk-protocol");
    }
}
