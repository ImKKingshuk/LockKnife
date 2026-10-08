"""Unit tests for Bluetooth passkey pairing implementation."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from lockknife.modules.exploitation.bluetooth.pairing import (
    PairingManager,
    PairingMethod,
    PairingState,
)


def test_pair_passkey_dry_run() -> None:
    """Test passkey pairing in dry run mode."""
    pm = PairingManager()
    result = pm.pair(
        "00:11:22:33:44:55",
        method=PairingMethod.PASSKEY,
        passkey="123456",
        dry_run=True,
    )
    assert result.success is True
    assert result.state == PairingState.PAIRED
    assert result.method == PairingMethod.PASSKEY
    assert result.pin_used == "123456"


def test_pair_passkey_with_explicit_passkey() -> None:
    """Test passkey pairing with automated bluetoothctl interaction."""
    pm = PairingManager()

    with patch("subprocess.run") as mock_run:
        # First call: agent KeyboardDisplay; Second call: pair; Third call: paired-devices check
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="Agent registered", stderr=""),
            MagicMock(returncode=0, stdout="Pairing successful\nDevice paired", stderr=""),
            MagicMock(returncode=0, stdout="Device 00:11:22:33:44:55 Phone", stderr=""),
        ]

        result = pm.pair(
            "00:11:22:33:44:55",
            method=PairingMethod.PASSKEY,
            passkey="654321",
            timeout_s=5.0,
            dry_run=False,
        )

        assert result.success is True
        assert result.state == PairingState.PAIRED
        assert result.pin_used == "654321"
        assert pm.is_paired("00:11:22:33:44:55")

        # Verify second call received passkey in input
        assert mock_run.call_count == 3
        pair_call_kwargs = mock_run.call_args_list[1][1]
        assert "654321\nyes\n" in pair_call_kwargs.get("input", "")


def test_pair_passkey_numeric_comparison() -> None:
    """Test passkey pairing numeric comparison auto-confirm without explicit passkey."""
    pm = PairingManager()

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="Device paired", stderr=""),
        ]

        result = pm.pair(
            "00:11:22:33:44:55",
            method=PairingMethod.PASSKEY,
            timeout_s=5.0,
            dry_run=False,
        )

        assert result.success is True
        assert result.state == PairingState.PAIRED
        pair_call_kwargs = mock_run.call_args_list[1][1]
        assert pair_call_kwargs.get("input") == "yes\n"


def test_pair_passkey_timeout() -> None:
    """Test passkey pairing when bluetoothctl times out."""
    pm = PairingManager()

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            subprocess.TimeoutExpired(cmd=["bluetoothctl"], timeout=5.0),
        ]

        result = pm.pair(
            "00:11:22:33:44:55",
            method=PairingMethod.PASSKEY,
            passkey="111111",
            timeout_s=5.0,
            dry_run=False,
        )

        assert result.success is False
        assert result.state == PairingState.TIMEOUT
        assert "timeout" in str(result.error).lower()
