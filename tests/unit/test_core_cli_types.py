import click
import pytest


def test_hash_hex_type_accepts_sha256() -> None:
    from lockknife.core.cli_types import HASH_HEX

    v = "A" * 64
    assert HASH_HEX.convert(v, None, None) == ("a" * 64)


def test_hash_hex_type_rejects_non_hex() -> None:
    from lockknife.core.cli_types import HASH_HEX

    with pytest.raises(click.BadParameter):
        HASH_HEX.convert("zz", None, None)


def test_ipv4_type_normalizes() -> None:
    from lockknife.core.cli_types import IPV4

    assert IPV4.convert("001.002.003.004", None, None) == "1.2.3.4"


def test_domain_type_rejects_invalid() -> None:
    from lockknife.core.cli_types import DOMAIN

    with pytest.raises(click.BadParameter):
        DOMAIN.convert("-bad.example", None, None)


def test_android_package_accepts() -> None:
    from lockknife.core.cli_types import ANDROID_PACKAGE

    assert ANDROID_PACKAGE.convert("com.example.app", None, None) == "com.example.app"
