//! Dependency-free SHA-256 (FIPS 180-4), used for diff fingerprints and webhook HMACs.
//!
//! # Why hand-rolled
//!
//! No SHA-256 implementation exists in `Cargo.lock` (`sha2` is absent) and Phase 07 does not add
//! crates — unlike `jsonptr`, which was already in the lock as a `json-patch` dependency and so
//! cost nothing to use directly. Hand-rolling a hash is normally the wrong call, and it is
//! acceptable here because every use is either a **non-authenticated fingerprint** or a MAC whose
//! secrecy comes from the key rather than from the hash:
//!
//! * Secret value redaction (`redact`), so a diff can prove *whether* a value changed
//!   without exposing it,
//! * `source_spec_hash` (`decision`), so an `Application.spec` edit that produces no new
//!   commit still triggers a sync (finding H7), and
//! * the `T14.2` GitHub `X-Hub-Signature-256` HMAC, which [`digest`] backs
//!   ([`crate::diff::sha256`] is the *only* SHA-256 in the workspace, so `ferriscd-server` builds
//!   its HMAC on top of it instead of adding a second hash implementation).
//!
//! The digests only ever answer "changed or not" for a value the caller already holds; the one
//! place a digest touches secret material is the redaction fingerprint, which is a truncated
//! (32-bit) prefix published precisely so drift stays visible — see the limitation noted in
//! `redact`.
//!
//! **Do not use this for password storage, signature *generation* with long-lived keys, or any
//! comparison that must be constant-time** — comparing two digests byte-by-byte leaks their
//! prefix, so HMAC verification must use a constant-time comparison (`subtle`, `ring`, or
//! `aws-lc`). A vetted implementation (`sha2`, `ring`, `aws-lc`) should replace this module the
//! moment it becomes a direct dependency.
//!
//! It is pinned to the published FIPS 180-4 known-answer vectors by the tests below.

/// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Initial hash state: first 32 bits of the fractional parts of the square roots of the
/// first 8 primes.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Lowercase hexadecimal digits.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// Computes the SHA-256 digest of `message`.
///
/// Public because it is the workspace's only SHA-256: `ferriscd-server` builds its `T14.2`
/// `X-Hub-Signature-256` HMAC on top of it rather than linking a second hash implementation.
/// Treat it as a primitive, not as an authentication API — see the module docs.
#[must_use]
pub fn digest(message: &[u8]) -> [u8; 32] {
    let bit_len = (message.len() as u64).wrapping_mul(8);
    // Pad to a multiple of 64 bytes: `0x80`, zero fill, then the 64-bit big-endian length.
    // A copied buffer keeps the function pure (`message` is never mutated) and keeps the
    // block loop trivially in-bounds.
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = H0;
    let (blocks, _remainder) = padded.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }

    let mut out = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Lowercase hexadecimal SHA-256 digest of `message` (64 characters).
pub(crate) fn hex_digest(message: &[u8]) -> String {
    let digest = digest(message);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

/// The first `hex_chars` characters of [`hex_digest`] (`hex_chars` is clamped to 64).
pub(crate) fn hex_digest_prefix(message: &[u8], hex_chars: usize) -> String {
    let mut hex = hex_digest(message);
    hex.truncate(hex_chars.min(64));
    hex
}

/// Applies the SHA-256 compression function to `state` for one 64-byte `block`.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0_u32; 64];
    for (index, slot) in schedule.iter_mut().take(16).enumerate() {
        let offset = index * 4;
        *slot = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let previous = schedule[index - 15];
        let prior = schedule[index - 2];
        let s0 = previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
        let s1 = prior.rotate_right(17) ^ prior.rotate_right(19) ^ (prior >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(K[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 / NIST known-answer vectors.
    #[test]
    fn known_answer_vectors_match() {
        let cases = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                hex_digest(message.as_bytes()),
                expected,
                "message {message:?}"
            );
        }
    }

    /// Lengths around the padding boundaries (55/56/63/64/119/120 bytes) exercise every
    /// padding branch: `0x80` before the length field, the extra block when it does not fit,
    /// and the exact-block boundary. Expected values were cross-checked with
    /// `python3 -c 'hashlib.sha256(b"a"*N).hexdigest()'`.
    #[test]
    fn padding_boundaries_are_handled() {
        let cases = [
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                119,
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            ),
            (
                120,
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            ),
        ];
        for (length, expected) in cases {
            let message = "a".repeat(length);
            assert_eq!(hex_digest(message.as_bytes()), expected, "length {length}");
            assert_eq!(
                hex_digest(message.as_bytes()),
                hex_digest(message.as_bytes()),
                "the digest must be deterministic"
            );
        }
    }

    /// The multi-block path must be a real Merkle-Damgård chain, not a single-block hash.
    #[test]
    fn long_messages_chain_blocks() {
        let thousand = vec![b'a'; 1_000];
        assert_eq!(
            hex_digest(&thousand),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );

        // The published FIPS 180-4 vector for 1,000,000 x 'a'.
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex_digest(&million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn prefixes_are_truncated_hex_digests() {
        let full = hex_digest(b"ferriscd");
        assert_eq!(hex_digest_prefix(b"ferriscd", 8), full[..8]);
        assert_eq!(hex_digest_prefix(b"ferriscd", 0), "");
        assert_eq!(hex_digest_prefix(b"ferriscd", 64), full);
        assert_eq!(
            hex_digest_prefix(b"ferriscd", 999),
            full,
            "the prefix length is clamped to the digest length"
        );
    }
}
