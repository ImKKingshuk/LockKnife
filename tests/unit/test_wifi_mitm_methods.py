"""Unit tests for WiFi MITM attack method expansion."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from lockknife.modules.exploitation.wifi.mitm import (
    MITMAttack,
    MITMConfig,
    MITMMethod,
    MITMState,
)


def test_mitm_dhcp_spoof() -> None:
    """Test starting DHCP spoofing MITM attack."""
    mitm = MITMAttack()
    config = MITMConfig(
        method=MITMMethod.DHCP_SPOOF,
        target="192.0.2.10",
        gateway="192.0.2.1",
        interface="wlan0",
    )

    with patch("subprocess.Popen") as mock_popen, patch("time.sleep"):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # running
        mock_popen.return_value = mock_proc

        result = mitm.start(config, duration_s=0.0)

        assert result.success is True
        assert result.state == MITMState.RUNNING


def test_mitm_ssl_strip() -> None:
    """Test starting SSL stripping MITM attack."""
    mitm = MITMAttack()
    config = MITMConfig(
        method=MITMMethod.SSL_STRIP,
        target="192.0.2.10",
        gateway="192.0.2.1",
        port=8080,
    )

    with patch("subprocess.Popen") as mock_popen, patch("time.sleep"):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        result = mitm.start(config, duration_s=0.0)

        assert result.success is True
        assert result.state == MITMState.RUNNING


def test_mitm_http_inject() -> None:
    """Test starting HTTP traffic injection attack."""
    mitm = MITMAttack()
    config = MITMConfig(
        method=MITMMethod.HTTP_INJECT,
        target="192.0.2.10",
        gateway="192.0.2.1",
        port=8080,
    )

    with patch("subprocess.Popen") as mock_popen, patch("time.sleep"):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        result = mitm.start(config, duration_s=0.0)

        assert result.success is True
        assert result.state == MITMState.RUNNING


def test_mitm_stop_cleanup() -> None:
    """Test stop cleanup terminating child and background processes."""
    mitm = MITMAttack()
    mock_proc = MagicMock()
    mitm._mitm_process = mock_proc

    with patch("subprocess.run") as mock_run:
        stopped = mitm.stop()

        assert stopped is True
        mock_proc.terminate.assert_called_once()
        assert mitm._mitm_process is None
        # Verify pkill was called for cleanup
        assert mock_run.call_count >= 1
