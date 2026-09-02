// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Result, bail};
use aws_lc_rs::hkdf;
use std::sync::LazyLock;

pub const WRAP_KEY_LEN: usize = 32;
const WRAP_SALT_BYTES: &[u8] = b"CSQTT-WRAP-v1";
const WRAP_INFO: &[u8] = b"rtp-obfs/chacha20poly1305";
static WRAP_SALT: LazyLock<hkdf::Salt> =
    LazyLock::new(|| hkdf::Salt::new(hkdf::HKDF_SHA256, WRAP_SALT_BYTES));

pub fn derive_wrap_key(password: &str) -> Result<[u8; WRAP_KEY_LEN]> {
    if password.is_empty() {
        bail!("empty password");
    }
    let prk = WRAP_SALT.extract(password.as_bytes());
    let info = [WRAP_INFO];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("derive wrap key"))?;
    let mut key = [0u8; WRAP_KEY_LEN];
    okm.fill(&mut key)
        .map_err(|_| anyhow::anyhow!("derive wrap key"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hkdf::Hkdf as RustCryptoHkdf;
    use sha2::Sha256;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn derive_rustcrypto(password: &str) -> [u8; WRAP_KEY_LEN] {
        let hk = RustCryptoHkdf::<Sha256>::new(Some(WRAP_SALT_BYTES), password.as_bytes());
        let mut key = [0u8; WRAP_KEY_LEN];
        hk.expand(WRAP_INFO, &mut key).unwrap();
        key
    }

    #[test]
    fn known_wire_vector() {
        let expected =
            hex::decode("aa77380e1203f9e02b705efd192b19020c011619af3d70b03e70c13658e373f4")
                .unwrap();
        assert_eq!(derive_rustcrypto("test-password"), expected.as_slice());
        assert_eq!(
            derive_wrap_key("test-password").unwrap(),
            expected.as_slice()
        );
    }

    #[test]
    fn deterministic_and_password_bound() {
        let first = derive_wrap_key("test-password").unwrap();
        let second = derive_wrap_key("test-password").unwrap();
        let other = derive_wrap_key("other-password").unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn rejects_empty_password() {
        assert!(derive_wrap_key("").is_err());
    }

    #[test]
    fn matches_rustcrypto_for_many_lengths_and_unicode() {
        for length in [
            1, 2, 3, 7, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 1024, 4096,
        ] {
            let password: String = (0..length)
                .map(|index| char::from(b'!' + (index % 90) as u8))
                .collect();
            assert_eq!(
                derive_wrap_key(&password).unwrap(),
                derive_rustcrypto(&password),
                "ASCII length {length}"
            );
        }

        for password in [
            "пароль",
            "こんにちは世界",
            "密碼🔐",
            "🙂🚀🛰️🌍",
            "e\u{301}cole",
            "école",
            "עברית-العربية",
            "\0внутри\0",
            "𝕽𝖚𝖘𝖙与Go",
            "a🙂б界".repeat(257).as_str(),
        ] {
            assert_eq!(
                derive_wrap_key(password).unwrap(),
                derive_rustcrypto(password),
                "Unicode password {password:?}"
            );
        }
    }

    #[test]
    fn concurrent_shared_native_calls_are_stable() {
        const THREADS: usize = 16;
        const CALLS_PER_THREAD: usize = 2_000;

        let password: Arc<str> = Arc::from("общий🔐native-password-密碼");
        let expected = derive_rustcrypto(&password);
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);

        for _ in 0..THREADS {
            let password = Arc::clone(&password);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..CALLS_PER_THREAD {
                    assert_eq!(derive_wrap_key(&password).unwrap(), expected);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    macro_rules! wrap_equivalence_case {
        ($name:ident, $password:expr) => {
            #[test]
            fn $name() {
                let password: &str = $password;
                assert_eq!(
                    derive_wrap_key(password).unwrap(),
                    derive_rustcrypto(password)
                );
            }
        };
    }

    wrap_equivalence_case!(wrap_key_ascii_single_byte, "a");
    wrap_equivalence_case!(wrap_key_ascii_with_space, "correct horse battery staple");
    wrap_equivalence_case!(wrap_key_leading_and_trailing_space, "  tunnel-secret  ");
    wrap_equivalence_case!(wrap_key_contains_newline, "line-one\nline-two");
    wrap_equivalence_case!(wrap_key_contains_tab, "before\tafter");
    wrap_equivalence_case!(wrap_key_contains_nul, "before\0after");
    wrap_equivalence_case!(wrap_key_cyrillic, "пароль-подключения");
    wrap_equivalence_case!(wrap_key_arabic, "كلمة-مرور-النفق");
    wrap_equivalence_case!(wrap_key_hebrew, "סיסמת-מנהרה");
    wrap_equivalence_case!(wrap_key_japanese, "トンネルのパスワード");
    wrap_equivalence_case!(wrap_key_chinese, "隧道密码");
    wrap_equivalence_case!(wrap_key_emoji, "🔐🚀🌍");
    wrap_equivalence_case!(wrap_key_composed_unicode, "école");
    wrap_equivalence_case!(wrap_key_decomposed_unicode, "e\u{301}cole");
    wrap_equivalence_case!(wrap_key_mixed_scripts, "Rust-Ржавчина-锈-🦀");
    wrap_equivalence_case!(wrap_key_control_byte, "prefix\u{0001}suffix");
    wrap_equivalence_case!(
        wrap_key_long_fixed_secret,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
}
