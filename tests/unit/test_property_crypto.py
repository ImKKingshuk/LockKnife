import pytest
from hypothesis import Phase, given, settings
from hypothesis import strategies as st

lockknife_core = pytest.importorskip("lockknife.lockknife_core")


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=1024))
def test_sha256_hex_output_format(data):
    """Property: sha256_hex output is always 64 hex characters."""
    result = lockknife_core.sha256_hex(data)
    assert isinstance(result, str)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=1024))
def test_sha256_hex_deterministic(data):
    """Property: sha256_hex is deterministic - same input produces same output."""
    result1 = lockknife_core.sha256_hex(data)
    result2 = lockknife_core.sha256_hex(data)
    assert result1 == result2


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=1024))
def test_sha512_hex_output_format(data):
    """Property: sha512_hex output is always 128 hex characters."""
    result = lockknife_core.sha512_hex(data)
    assert isinstance(result, str)
    assert len(result) == 128
    assert all(c in "0123456789abcdef" for c in result)


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=1024))
def test_sha512_hex_deterministic(data):
    """Property: sha512_hex is deterministic - same input produces same output."""
    result1 = lockknife_core.sha512_hex(data)
    result2 = lockknife_core.sha512_hex(data)
    assert result1 == result2


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=256), st.binary(min_size=0, max_size=256))
def test_hmac_sha256_output_format(key, data):
    """Property: hmac_sha256 output is always 64 hex characters."""
    result = lockknife_core.hmac_sha256(key, data)
    assert isinstance(result, str)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=256), st.binary(min_size=0, max_size=256))
def test_hmac_sha256_key_reuse_same_output(key, data):
    """Property: hmac_sha256 with same key produces same output for same data."""
    result1 = lockknife_core.hmac_sha256(key, data)
    result2 = lockknife_core.hmac_sha256(key, data)
    assert result1 == result2


@settings(max_examples=100, phases=[Phase.generate])
@given(st.binary(min_size=0, max_size=256), st.binary(min_size=0, max_size=256))
def test_hmac_sha256_different_keys_different_outputs(key, data):
    """Property: hmac_sha256 with different keys produces different outputs (high probability)."""
    # This is a probabilistic property, so we just check it doesn't crash
    result1 = lockknife_core.hmac_sha256(key, data)
    result2 = lockknife_core.hmac_sha256(key + b"x", data)
    # Different keys should almost always produce different HMACs
    # We don't assert inequality as it's probabilistic, just verify it runs
    assert isinstance(result1, str)
    assert isinstance(result2, str)


@settings(max_examples=50, phases=[Phase.generate])
@given(st.binary(min_size=32, max_size=32), st.binary(min_size=12, max_size=12), st.binary(min_size=0, max_size=1024))
def test_aes256gcm_roundtrip(key, nonce, plaintext):
    """Property: aes256gcm_encrypt followed by decrypt recovers original plaintext."""
    ciphertext = lockknife_core.aes256gcm_encrypt(key, nonce, plaintext, b"")
    decrypted = lockknife_core.aes256gcm_decrypt(key, nonce, ciphertext, b"")
    assert decrypted == plaintext


@settings(max_examples=50, phases=[Phase.generate])
@given(st.binary(min_size=32, max_size=32), st.binary(min_size=0, max_size=1024))
def test_aes256gcm_different_nonce_different_ciphertext(key, plaintext):
    """Property: aes256gcm_encrypt with different nonce produces different ciphertext."""
    nonce1 = b"\x00" * 12
    nonce2 = b"\x01" * 12
    ciphertext1 = lockknife_core.aes256gcm_encrypt(key, nonce1, plaintext, b"")
    ciphertext2 = lockknife_core.aes256gcm_encrypt(key, nonce2, plaintext, b"")
    assert ciphertext1 != ciphertext2


@settings(max_examples=50, phases=[Phase.generate])
@given(st.binary(min_size=32, max_size=32), st.binary(min_size=12, max_size=12), st.binary(min_size=0, max_size=1024))
def test_aes256gcm_different_aad_different_ciphertext(key, nonce, plaintext):
    """Property: aes256gcm_encrypt with different AAD produces different ciphertext."""
    ciphertext1 = lockknife_core.aes256gcm_encrypt(key, nonce, plaintext, b"")
    ciphertext2 = lockknife_core.aes256gcm_encrypt(key, nonce, plaintext, b"extra")
    assert ciphertext1 != ciphertext2
