//! Fixed-suite cryptography: RFC 9180 HPKE Base mode with
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM; Ed25519 with
//! strict verification; SHA-256. No suite negotiation, no key conversion.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The one HPKE suite: KEM 0x0020, KDF 0x0001, AEAD 0x0002.
pub type Kem = hpke::kem::X25519HkdfSha256;
pub type Kdf = hpke::kdf::HkdfSha256;
pub type Aead = hpke::aead::AesGcm256;
pub type HpkePrivateKey = <Kem as hpke::Kem>::PrivateKey;

/// Every sealed value starts with the 32-byte X25519 encapsulated key.
const ENC_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// Any cryptographic failure. It carries nothing on purpose: callers map it
/// to the protocol code that fits their context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

/// Seal `plaintext` to `recipient` (HPKE Base mode, single shot) with empty
/// AAD: all context goes in `info`, as RFC 9180 §8.1 asks of single-shot
/// use. Returns `enc ‖ ciphertext ‖ tag`, the layout pyca/cryptography uses.
///
/// Dependency limitation: hpke 0.14.1 takes its ephemeral randomness through
/// an infallible RNG interface, so an OS RNG failure panics inside this call
/// instead of returning an error. There is no fallback source. The binary is
/// built with `panic = "abort"`, so the process ends before anything is
/// sealed, sent or committed.
pub fn seal(recipient: &[u8; 32], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let recipient =
        <Kem as hpke::Kem>::PublicKey::from_bytes(recipient).map_err(|_| CryptoError)?;
    let (enc, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &recipient, info, plaintext, b"")
            .map_err(|_| CryptoError)?;
    let mut sealed = enc.to_bytes().to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Open a value produced by [`seal`]. The plaintext is wiped when dropped.
pub fn open(
    key: &HpkePrivateKey,
    info: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < ENC_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (enc, ciphertext) = sealed.split_at(ENC_LEN);
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| CryptoError)?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, key, &enc, info, ciphertext, b"")
        .map(Zeroizing::new)
        .map_err(|_| CryptoError)
}

/// Any 32 bytes are a usable X25519 private key; clamping happens on use.
pub fn hpke_private_key(bytes: &[u8; 32]) -> Result<HpkePrivateKey, CryptoError> {
    HpkePrivateKey::from_bytes(bytes).map_err(|_| CryptoError)
}

pub fn hpke_public_key(key: &HpkePrivateKey) -> [u8; 32] {
    let mut public = [0u8; 32];
    public.copy_from_slice(&Kem::sk_to_pk(key).to_bytes());
    public
}

/// Ed25519 `verify_strict`: refuses small-order keys and non-canonical
/// signatures, not only invalid ones.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError)
}

/// A key `verify` could ever accept: a valid point of large order.
pub fn is_usable_verifying_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| !key.is_weak())
}

pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (HpkePrivateKey, [u8; 32]) {
        let key = hpke_private_key(&[7; 32]).unwrap();
        let public = hpke_public_key(&key);
        (key, public)
    }

    #[test]
    fn sealed_values_open_only_with_the_same_info_and_key() {
        let (key, public) = keypair();
        let sealed = seal(&public, b"info", b"envelope").unwrap();
        assert_eq!(sealed.len(), ENC_LEN + b"envelope".len() + TAG_LEN);
        assert_eq!(
            open(&key, b"info", &sealed).unwrap().as_slice(),
            b"envelope"
        );

        assert_eq!(open(&key, b"other info", &sealed), Err(CryptoError));
        let other = hpke_private_key(&[8; 32]).unwrap();
        assert_eq!(open(&other, b"info", &sealed), Err(CryptoError));
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, b"info", &flipped), Err(CryptoError));
        assert_eq!(
            open(&key, b"info", &sealed[..ENC_LEN + TAG_LEN - 1]),
            Err(CryptoError)
        );
    }

    /// RFC 9180 §7.1.4: an all-zero shared secret aborts both directions.
    #[test]
    fn low_order_points_are_refused() {
        let (key, public) = keypair();
        let mut sealed = seal(&public, b"info", b"x").unwrap();
        sealed[..ENC_LEN].fill(0);
        assert_eq!(open(&key, b"info", &sealed), Err(CryptoError));
        assert_eq!(seal(&[0; 32], b"info", b"x"), Err(CryptoError));
    }

    #[test]
    fn verification_is_strict() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let public = signing.verifying_key().to_bytes();
        let signature = sign(&signing, b"message");
        assert_eq!(verify(&public, b"message", &signature), Ok(()));
        assert_eq!(verify(&public, b"other", &signature), Err(CryptoError));

        // The identity point is a small-order key: some signatures verify
        // under non-strict rules, never under `verify_strict`.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!is_usable_verifying_key(&identity));
        assert!(is_usable_verifying_key(&public));
    }
}
