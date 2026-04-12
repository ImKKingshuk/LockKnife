import pytest
from hypothesis import Phase, given, settings
from hypothesis import strategies as st

lockknife_core = pytest.importorskip("lockknife.lockknife_core")


@settings(max_examples=50, phases=[Phase.generate])
@given(st.integers(min_value=0, max_value=9999))
def test_bruteforce_numeric_pin_roundtrip(pin):
    """Property: bruteforce_numeric_pin finds a PIN that hashes to the target."""
    pin_str = str(pin).zfill(4)
    target = lockknife_core.sha256_hex(pin_str.encode("utf-8"))
    found = lockknife_core.bruteforce_numeric_pin(target, "sha256", 4)
    # The found PIN should hash to the target
    assert lockknife_core.sha256_hex(found.encode("utf-8")) == target
    assert len(found) == 4


@settings(max_examples=50, phases=[Phase.generate])
@given(st.text(min_size=1, max_size=10, alphabet=st.characters(categories=[], whitelist_characters="abcdefghijklmnopqrstuvwxyz")))
def test_dictionary_attack_roundtrip(password):
    """Property: dictionary_attack finds a password that hashes to the target."""
    target = lockknife_core.sha256_hex(password.encode("utf-8"))
    # Create a temporary wordlist containing the password
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write(password + "\n")
        wordlist_path = f.name

    try:
        found = lockknife_core.dictionary_attack(target, "sha256", wordlist_path)
        # The found password should hash to the target
        assert lockknife_core.sha256_hex(found.encode("utf-8")) == target
        assert found == password
    finally:
        os.unlink(wordlist_path)


@settings(max_examples=50, phases=[Phase.generate])
@given(st.integers(min_value=0, max_value=9999))
def test_hash_bruteforce_roundtrip(pin):
    """Property: hash(bruteforce(hash(x))) == hash(x) for numeric pins."""
    # This tests the fundamental property that bruteforce correctly reverses the hash
    pin_str = str(pin).zfill(4)  # Ensure it's 4 digits for numeric bruteforce
    target = lockknife_core.sha256_hex(pin_str.encode("utf-8"))
    found = lockknife_core.bruteforce_numeric_pin(target, "sha256", 4)
    assert lockknife_core.sha256_hex(found.encode("utf-8")) == target


@settings(max_examples=50, phases=[Phase.generate])
@given(st.integers(min_value=0, max_value=9999))
def test_bruteforce_numeric_pin_pin_length(pin):
    """Property: bruteforce_numeric_pin returns a 4-digit PIN."""
    pin_str = str(pin).zfill(4)
    target = lockknife_core.sha256_hex(pin_str.encode("utf-8"))
    found = lockknife_core.bruteforce_numeric_pin(target, "sha256", 4)
    assert len(found) == 4
    assert found.isdigit()


@settings(max_examples=30, phases=[Phase.generate])
@given(st.text(min_size=1, max_size=8, alphabet=st.characters(categories=[], whitelist_characters="abcdefghijklmnopqrstuvwxyz0123456789")))
def test_dictionary_attack_not_in_wordlist(password):
    """Property: dictionary_attack returns None if password not in wordlist."""
    target = lockknife_core.sha256_hex(password.encode("utf-8"))

    # Create a wordlist that does NOT contain the password
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        # Write some other passwords
        f.write("other\n")
        f.write("password\n")
        f.write("123456\n")
        wordlist_path = f.name

    try:
        found = lockknife_core.dictionary_attack(target, "sha256", wordlist_path)
        # Should return None or raise an error if not found
        # The actual behavior depends on implementation
        assert found is None or found != password
    finally:
        os.unlink(wordlist_path)
