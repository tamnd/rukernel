// rk-abigen generated this file from Linux 7.3, from <linux/keyctl.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The operations of `keyctl`, the special key ring IDs and the default key rings.

/// - key ID for request\_key() dest keyring.
pub const KEY_SPEC_REQUESTOR_KEYRING: i32 = -8;
/// - key ID for assumed request\_key auth key.
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;
/// - key ID for GID-specific keyring.
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
/// - key ID for UID-session keyring.
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// - key ID for UID-specific keyring.
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// - key ID for session-specific keyring.
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// - key ID for process-specific keyring.
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// `KEY_REQKEY_DEFL_NO_CHANGE` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_NO_CHANGE: i32 = -1;
/// - key ID for thread-specific keyring.
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
/// Ask for a keyring's ID.
pub const KEYCTL_GET_KEYRING_ID: i32 = 0;
/// `KEY_REQKEY_DEFL_DEFAULT` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_DEFAULT: i32 = 0;
/// KEYCTL\_CAPABILITIES supported.
pub const KEYCTL_CAPS0_CAPABILITIES: i32 = 1;
/// Keyring names are per-user\_namespace.
pub const KEYCTL_CAPS1_NS_KEYRING_NAME: i32 = 1;
/// Join or start named session keyring.
pub const KEYCTL_JOIN_SESSION_KEYRING: i32 = 1;
/// Do not displace from the to-keyring.
pub const KEYCTL_MOVE_EXCL: i32 = 1;
/// `KEYCTL_SUPPORTS_ENCRYPT` from `<linux/keyctl.h>`.
pub const KEYCTL_SUPPORTS_ENCRYPT: i32 = 1;
/// `KEY_REQKEY_DEFL_THREAD_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_THREAD_KEYRING: i32 = 1;
/// Persistent keyrings enabled.
pub const KEYCTL_CAPS0_PERSISTENT_KEYRINGS: i32 = 2;
/// Key indexing can include a namespace tag.
pub const KEYCTL_CAPS1_NS_KEY_TAG: i32 = 2;
/// `KEYCTL_SUPPORTS_DECRYPT` from `<linux/keyctl.h>`.
pub const KEYCTL_SUPPORTS_DECRYPT: i32 = 2;
/// Update a key.
pub const KEYCTL_UPDATE: i32 = 2;
/// `KEY_REQKEY_DEFL_PROCESS_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_PROCESS_KEYRING: i32 = 2;
/// Revoke a key.
pub const KEYCTL_REVOKE: i32 = 3;
/// `KEY_REQKEY_DEFL_SESSION_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_SESSION_KEYRING: i32 = 3;
/// Diffie-Hellman computation enabled.
pub const KEYCTL_CAPS0_DIFFIE_HELLMAN: i32 = 4;
/// Keys generate watchable notifications.
pub const KEYCTL_CAPS1_NOTIFICATIONS: i32 = 4;
/// Set ownership of a key.
pub const KEYCTL_CHOWN: i32 = 4;
/// `KEYCTL_SUPPORTS_SIGN` from `<linux/keyctl.h>`.
pub const KEYCTL_SUPPORTS_SIGN: i32 = 4;
/// `KEY_REQKEY_DEFL_USER_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_USER_KEYRING: i32 = 4;
/// Set perms on a key.
pub const KEYCTL_SETPERM: i32 = 5;
/// `KEY_REQKEY_DEFL_USER_SESSION_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_USER_SESSION_KEYRING: i32 = 5;
/// Describe a key.
pub const KEYCTL_DESCRIBE: i32 = 6;
/// `KEY_REQKEY_DEFL_GROUP_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_GROUP_KEYRING: i32 = 6;
/// Clear contents of a keyring.
pub const KEYCTL_CLEAR: i32 = 7;
/// `KEY_REQKEY_DEFL_REQUESTOR_KEYRING` from `<linux/keyctl.h>`.
pub const KEY_REQKEY_DEFL_REQUESTOR_KEYRING: i32 = 7;
/// Public key ops enabled.
pub const KEYCTL_CAPS0_PUBLIC_KEY: i32 = 8;
/// Link a key into a keyring.
pub const KEYCTL_LINK: i32 = 8;
/// `KEYCTL_SUPPORTS_VERIFY` from `<linux/keyctl.h>`.
pub const KEYCTL_SUPPORTS_VERIFY: i32 = 8;
/// Unlink a key from a keyring.
pub const KEYCTL_UNLINK: i32 = 9;
/// Search for a key in a keyring.
pub const KEYCTL_SEARCH: i32 = 10;
/// Read a key or keyring's contents.
pub const KEYCTL_READ: i32 = 11;
/// Instantiate a partially constructed key.
pub const KEYCTL_INSTANTIATE: i32 = 12;
/// Negate a partially constructed key.
pub const KEYCTL_NEGATE: i32 = 13;
/// Set default request-key keyring.
pub const KEYCTL_SET_REQKEY_KEYRING: i32 = 14;
/// Set key timeout.
pub const KEYCTL_SET_TIMEOUT: i32 = 15;
/// Assume request\_key() authorisation.
pub const KEYCTL_ASSUME_AUTHORITY: i32 = 16;
/// Big\_key-type enabled.
pub const KEYCTL_CAPS0_BIG_KEY: i32 = 16;
/// Get key security label.
pub const KEYCTL_GET_SECURITY: i32 = 17;
/// Apply session keyring to parent process.
pub const KEYCTL_SESSION_TO_PARENT: i32 = 18;
/// Reject a partially constructed key.
pub const KEYCTL_REJECT: i32 = 19;
/// Instantiate a partially constructed key.
pub const KEYCTL_INSTANTIATE_IOV: i32 = 20;
/// Invalidate a key.
pub const KEYCTL_INVALIDATE: i32 = 21;
/// Get a user's persistent keyring.
pub const KEYCTL_GET_PERSISTENT: i32 = 22;
/// Compute Diffie-Hellman values.
pub const KEYCTL_DH_COMPUTE: i32 = 23;
/// Query public key parameters.
pub const KEYCTL_PKEY_QUERY: i32 = 24;
/// Encrypt a blob using a public key.
pub const KEYCTL_PKEY_ENCRYPT: i32 = 25;
/// Decrypt a blob using a public key.
pub const KEYCTL_PKEY_DECRYPT: i32 = 26;
/// Create a public key signature.
pub const KEYCTL_PKEY_SIGN: i32 = 27;
/// Verify a public key signature.
pub const KEYCTL_PKEY_VERIFY: i32 = 28;
/// Restrict keys allowed to link to a keyring.
pub const KEYCTL_RESTRICT_KEYRING: i32 = 29;
/// Move keys between keyrings.
pub const KEYCTL_MOVE: i32 = 30;
/// Find capabilities of keyrings subsystem.
pub const KEYCTL_CAPABILITIES: i32 = 31;
/// KEYCTL\_INVALIDATE supported.
pub const KEYCTL_CAPS0_INVALIDATE: i32 = 32;
/// Watch a key or ring of keys for changes.
pub const KEYCTL_WATCH_KEY: i32 = 32;
/// KEYCTL\_RESTRICT\_KEYRING supported.
pub const KEYCTL_CAPS0_RESTRICT_KEYRING: i32 = 64;
/// KEYCTL\_MOVE supported.
pub const KEYCTL_CAPS0_MOVE: i32 = 128;
