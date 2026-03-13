use md5::Md5;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ring::aead;
use ring::digest;
use ring::hmac;

const MAX_HASH_BYTES: usize = 1024 * 1024 * 1024;
const MAX_AES_BYTES: usize = 256 * 1024 * 1024;

fn validate_input(data: &[u8], limit: usize) -> PyResult<()> {
    if data.len() > limit {
        return Err(PyValueError::new_err("input exceeds size limit"));
    }
    Ok(())
}

#[pyfunction]
pub fn sha1_hex(data: &[u8]) -> PyResult<String> {
    validate_input(data, MAX_HASH_BYTES)?;
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    Ok(hex::encode(d.as_ref()))
}

#[pyfunction]
pub fn sha256_hex(data: &[u8]) -> PyResult<String> {
    validate_input(data, MAX_HASH_BYTES)?;
    let d = digest::digest(&digest::SHA256, data);
    Ok(hex::encode(d.as_ref()))
}

#[pyfunction]
pub fn sha512_hex(data: &[u8]) -> PyResult<String> {
    validate_input(data, MAX_HASH_BYTES)?;
    let d = digest::digest(&digest::SHA512, data);
    Ok(hex::encode(d.as_ref()))
}

#[pyfunction]
pub fn md5_hex(data: &[u8]) -> PyResult<String> {
    validate_input(data, MAX_HASH_BYTES)?;
    let mut hasher = Md5::default();
    md5::Digest::update(&mut hasher, data);
    let digest = md5::Digest::finalize(hasher);
    Ok(hex::encode(digest))
}

#[pyfunction]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> PyResult<String> {
    validate_input(key, MAX_HASH_BYTES)?;
    validate_input(data, MAX_HASH_BYTES)?;
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    Ok(hex::encode(tag.as_ref()))
}

#[pyfunction]
pub fn aes256gcm_encrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("nonce must be 12 bytes"));
    }
    validate_input(plaintext, MAX_AES_BYTES)?;
    validate_input(associated_data, MAX_AES_BYTES)?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| PyValueError::new_err("invalid key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| PyValueError::new_err("invalid nonce"))?;
    let aad = aead::Aad::from(associated_data);

    let mut in_out = plaintext.to_vec();
    in_out.reserve(aead::AES_256_GCM.tag_len());
    key.seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|_| PyValueError::new_err("encryption failed"))?;
    Ok(PyBytes::new_bound(py, &in_out).unbind())
}

#[pyfunction]
pub fn aes256gcm_decrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("nonce must be 12 bytes"));
    }
    validate_input(ciphertext, MAX_AES_BYTES)?;
    validate_input(associated_data, MAX_AES_BYTES)?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| PyValueError::new_err("invalid key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| PyValueError::new_err("invalid nonce"))?;
    let aad = aead::Aad::from(associated_data);

    let mut in_out = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|_| PyValueError::new_err("decryption failed"))?;
    Ok(PyBytes::new_bound(py, plain).unbind())
}

#[cfg(test)]
mod tests {
    use super::{
        aes256gcm_decrypt, aes256gcm_encrypt, hmac_sha256, md5_hex, sha1_hex, sha256_hex,
        sha512_hex,
    };
    use pyo3::Python;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
        });
    }

    #[test]
    fn test_hash_vectors() {
        assert_eq!(
            sha1_hex(b"abc").unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha256_hex(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha512_hex(b"abc").unwrap(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        assert_eq!(md5_hex(b"abc").unwrap(), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_hmac_vector() {
        let out = hmac_sha256(b"key", b"data").unwrap();
        assert_eq!(
            out,
            "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
        );
    }

    #[test]
    fn test_aes_roundtrip() {
        init_python();
        Python::with_gil(|py| {
            let key = [0u8; 32];
            let nonce = [1u8; 12];
            let ct = aes256gcm_encrypt(py, &key, &nonce, b"hello", b"").unwrap();
            let pt = aes256gcm_decrypt(py, &key, &nonce, ct.as_bytes(py), b"").unwrap();
            assert_eq!(pt.as_bytes(py), b"hello");
        });
    }

    #[test]
    fn test_invalid_key() {
        init_python();
        Python::with_gil(|py| {
            let key = [0u8; 16];
            let nonce = [0u8; 12];
            let err = aes256gcm_encrypt(py, &key, &nonce, b"hi", b"").unwrap_err();
            assert!(format!("{err}").contains("key"));
        });
    }
}
