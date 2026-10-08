"""Unit tests for ADB TCP Physical Forensics Stream Extraction."""

from __future__ import annotations

import pathlib
from unittest.mock import MagicMock, patch

from lockknife.modules.exploitation.adb_tcp.extractor import (
    DataExtractor,
    ExtractionResult,
    ExtractionType,
)


def test_physical_extraction_streaming(tmp_path: pathlib.Path) -> None:
    """Test physical extraction streaming directly without staging."""
    extractor = DataExtractor(output_dir=tmp_path)
    result = ExtractionResult(extraction_type=ExtractionType.PHYSICAL)

    def fake_stream_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "id" in cmd:
            return MagicMock(returncode=0, stdout="uid=0(root) gid=0(root)")
        if "exec-out" in cmd:
            # Simulate streaming dd raw bytes to stdout file
            f_out = kwargs.get("stdout")
            if f_out and hasattr(f_out, "write"):
                f_out.write(b"RAW_PARTITION_DATA" * 64)
            return MagicMock(returncode=0)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=fake_stream_run) as mock_run:
        extracted = extractor._physical_extraction("192.0.2.100:5555", result)

        assert extracted.total_files == 4  # system, data, cache, boot
        assert extracted.total_bytes > 0
        # Verify exec-out was called
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert any("exec-out" in cmd for cmd in calls)


def test_physical_extraction_fallback_cleanup(tmp_path: pathlib.Path) -> None:
    """Test physical extraction fallback staging cleans up remote files on device."""
    extractor = DataExtractor(output_dir=tmp_path)
    result = ExtractionResult(extraction_type=ExtractionType.PHYSICAL)

    def fake_fallback_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "id" in cmd:
            return MagicMock(returncode=0, stdout="uid=0(root) gid=0(root)")
        if "exec-out" in cmd:
            return MagicMock(returncode=1)  # exec-out unsupported
        return MagicMock(returncode=0)

    def fake_pull(target: str, remote: str, local: pathlib.Path) -> tuple[bool, pathlib.Path]:
        local.write_bytes(b"STAGED_DATA")
        return True, local

    with patch("subprocess.run", side_effect=fake_fallback_run) as mock_run:
        with patch.object(extractor, "pull_file", side_effect=fake_pull):
            extracted = extractor._physical_extraction("192.0.2.100:5555", result)

            assert extracted.total_files == 4
            calls = [c[0][0] for c in mock_run.call_args_list]
            # Ensure cleanup rm -f was invoked for all partitions
            cleanup_calls = [cmd for cmd in calls if "rm -f" in " ".join(cmd)]
            assert len(cleanup_calls) == 4
