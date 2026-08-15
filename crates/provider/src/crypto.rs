//! Secret Service `dh-ietf1024-sha256-aes128-cbc-pkcs7` sessions.

use aes::Aes128;
use cbc::{
    Decryptor, Encryptor,
    cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7},
};
use num_bigint::{BigUint, RandBigInt};
use rand_08::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ProviderError, Result};

const DH_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404D",
    "DEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C",
    "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
const DH_GROUP_BYTES: usize = 128;

fn dh_prime() -> BigUint {
    BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16).expect("RFC 2409 DH group is valid")
}

/// A per-caller session key. It is wiped when the D-Bus client disconnects.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SessionKey {
    Plain,
    Dh { key: [u8; 16] },
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => formatter.write_str("SessionKey::Plain"),
            Self::Dh { .. } => formatter.write_str("SessionKey::Dh([REDACTED])"),
        }
    }
}

impl SessionKey {
    #[must_use]
    pub fn plain() -> Self {
        Self::Plain
    }

    /// Performs the server side of the standard Secret Service DH handshake.
    pub fn open_dh(client_public: &[u8]) -> Result<(Self, Vec<u8>)> {
        if client_public.is_empty() || client_public.len() > 128 {
            return Err(ProviderError::InvalidRequest(
                "invalid DH public key".to_owned(),
            ));
        }
        let prime = dh_prime();
        let client = BigUint::from_bytes_be(client_public);
        let two = BigUint::from(2_u8);
        if client < two || client >= (&prime - &two) {
            return Err(ProviderError::InvalidRequest(
                "invalid DH public key".to_owned(),
            ));
        }

        // A 256-bit exponent is sufficient for this legacy compatibility
        // protocol and avoids retaining a full-width private value.
        let mut private = OsRng
            .gen_biguint_range(&two, &(&prime - &two))
            .to_bytes_be();
        let private_number = BigUint::from_bytes_be(&private);
        let server = BigUint::from(2_u8).modpow(&private_number, &prime);
        let shared = client.modpow(&private_number, &prime);
        private.zeroize();

        let key = derive_dh_aes_key(&shared);
        Ok((Self::Dh { key }, server.to_bytes_be()))
    }

    pub fn encrypt(&self, parameters: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Plain => {
                if !parameters.is_empty() {
                    return Err(ProviderError::InvalidRequest(
                        "plain sessions require empty parameters".to_owned(),
                    ));
                }
                Ok(secret.to_vec())
            }
            Self::Dh { key } => {
                let iv = checked_iv(parameters)?;
                Ok(Encryptor::<Aes128>::new(key.into(), iv.into())
                    .encrypt_padded_vec::<Pkcs7>(secret))
            }
        }
    }

    pub fn decrypt(&self, parameters: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Plain => {
                if !parameters.is_empty() {
                    return Err(ProviderError::InvalidRequest(
                        "plain sessions require empty parameters".to_owned(),
                    ));
                }
                Ok(encrypted.to_vec())
            }
            Self::Dh { key } => {
                let iv = checked_iv(parameters)?;
                let mut value = encrypted.to_vec();
                let result = Decryptor::<Aes128>::new(key.into(), iv.into())
                    .decrypt_padded::<Pkcs7>(&mut value)
                    .map(<[u8]>::to_vec);
                value.zeroize();
                result.map_err(|_| {
                    ProviderError::InvalidRequest("invalid encrypted secret".to_owned())
                })
            }
        }
    }
}

fn derive_dh_aes_key(shared: &BigUint) -> [u8; 16] {
    // libsecret pads the DH result to the 1024-bit group width before HKDF.
    let mut encoded = shared.to_bytes_be();
    debug_assert!(encoded.len() <= DH_GROUP_BYTES);
    let mut padded = [0_u8; DH_GROUP_BYTES];
    padded[DH_GROUP_BYTES - encoded.len()..].copy_from_slice(&encoded);
    encoded.zeroize();
    let key = derive_aes_key(&padded);
    padded.zeroize();
    key
}

fn checked_iv(parameters: &[u8]) -> Result<&[u8; 16]> {
    parameters.try_into().map_err(|_| {
        ProviderError::InvalidRequest("DH sessions require a 16-byte AES-CBC IV".to_owned())
    })
}

fn derive_aes_key(shared_secret: &[u8]) -> [u8; 16] {
    // Secret Service uses HKDF-SHA256 with a NULL salt and empty info.
    let mut pseudorandom_key = hmac_sha256(&[0; 32], shared_secret);
    let mut output = hmac_sha256(&pseudorandom_key, &[1]);
    pseudorandom_key.zeroize();
    let mut key = [0; 16];
    key.copy_from_slice(&output[..16]);
    output.zeroize();
    key
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut padded_key = [0; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut digest = Sha256::digest(key);
        padded_key[..digest.len()].copy_from_slice(&digest);
        digest.zeroize();
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + value.len());
    inner.extend(padded_key.iter().map(|byte| *byte ^ 0x36));
    inner.extend_from_slice(value);
    let mut inner_hash = Sha256::digest(&inner);
    inner.zeroize();

    let mut outer = Vec::with_capacity(BLOCK_SIZE + inner_hash.len());
    outer.extend(padded_key.iter().map(|byte| *byte ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    inner_hash.zeroize();
    padded_key.zeroize();
    let output: [u8; 32] = Sha256::digest(&outer).into();
    outer.zeroize();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_round_trip_and_wrong_key_rejection() {
        let prime = dh_prime();
        let client_private = BigUint::from(42_u8);
        let client_public = BigUint::from(2_u8)
            .modpow(&client_private, &prime)
            .to_bytes_be();
        let (server, server_public) = SessionKey::open_dh(&client_public).unwrap();
        let shared = BigUint::from_bytes_be(&server_public).modpow(&client_private, &prime);
        let client = SessionKey::Dh {
            key: derive_dh_aes_key(&shared),
        };
        let iv = [7_u8; 16];
        let ciphertext = client
            .encrypt(&iv, b"binary\0unicode \xF0\x9F\x94\x90")
            .unwrap();
        assert_eq!(
            server.decrypt(&iv, &ciphertext).unwrap(),
            b"binary\0unicode \xF0\x9F\x94\x90"
        );
        assert_ne!(
            server.decrypt(&[0; 16], &ciphertext).unwrap(),
            b"binary\0unicode \xF0\x9F\x94\x90"
        );
    }

    #[test]
    fn aes_cbc_known_answer_first_block() {
        // NIST SP 800-38A AES-CBC key/IV/plaintext test vector. PKCS#7 adds
        // a second block, so the known first ciphertext block remains exact.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let session = SessionKey::Dh { key };
        let ciphertext = session.encrypt(&iv, &plain).unwrap();
        assert_eq!(
            &ciphertext[..16],
            &[
                0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
                0x19, 0x7d,
            ]
        );
        assert_eq!(session.decrypt(&iv, &ciphertext).unwrap(), plain);
    }

    #[test]
    fn plain_sessions_reject_crypto_parameters() {
        assert!(SessionKey::plain().encrypt(&[1], b"secret").is_err());
    }

    #[test]
    fn dh_rejects_malformed_public_keys_ivs_and_ciphertexts() {
        let prime = dh_prime();
        assert!(SessionKey::open_dh(&[]).is_err());
        assert!(SessionKey::open_dh(&[1]).is_err());
        assert!(SessionKey::open_dh(&prime.to_bytes_be()).is_err());

        let session = SessionKey::Dh { key: [7; 16] };
        assert!(session.encrypt(&[0; 15], &[1]).is_err());
        assert!(session.decrypt(&[0; 17], &[1]).is_err());
        assert!(session.decrypt(&[0; 16], &[0; 16]).is_err());
    }

    #[test]
    fn session_key_debug_output_is_redacted() {
        let output = format!("{:?}", SessionKey::Dh { key: [0xA5; 16] });
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("165"));
    }

    #[test]
    fn derives_the_secret_service_hkdf_key() {
        assert_eq!(
            derive_aes_key(&[0x0b; 22]),
            [
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31,
            ]
        );
    }

    #[test]
    fn dh_key_derivation_pads_to_the_group_width() {
        let mut shared_bytes = vec![0x42_u8; DH_GROUP_BYTES - 1];
        let shared = BigUint::from_bytes_be(&shared_bytes);
        let key = derive_dh_aes_key(&shared);

        let mut padded = [0_u8; DH_GROUP_BYTES];
        padded[1..].copy_from_slice(&shared_bytes);
        assert_eq!(key, derive_aes_key(&padded));

        let mut unpadded = shared.to_bytes_be();
        assert_ne!(key, derive_aes_key(&unpadded));
        padded.zeroize();
        unpadded.zeroize();
        shared_bytes.zeroize();
    }
}
