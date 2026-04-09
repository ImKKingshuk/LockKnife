import pytest
from hypothesis import given, settings, strategies as st
from hypothesis import Phase
from pathlib import Path

from lockknife.core.path_safety import (
    validate_user_path_text,
    validate_relative_component,
    ensure_child_path,
    validate_archive_member,
)


@settings(max_examples=100, phases=[Phase.generate])
@given(st.text())
def test_validate_user_path_text_empty_raises(text):
    """Property: validate_user_path_text raises on empty or whitespace-only input."""
    stripped = text.strip()
    # Check for control characters first (implementation checks before empty)
    has_control = any(ord(ch) < 32 for ch in stripped)
    if has_control:
        with pytest.raises(ValueError, match="control characters"):
            validate_user_path_text(text, label="path")
    elif not stripped:
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_user_path_text(text, label="path")
    else:
        # Should not raise for valid text
        result = validate_user_path_text(text, label="path")
        assert result == stripped


@settings(max_examples=100, phases=[Phase.generate])
@given(st.text())
def test_validate_user_path_text_control_chars_rejected(text):
    """Property: validate_user_path_text rejects strings with control characters."""
    stripped = text.strip()
    if not stripped:
        # Empty strings raise "cannot be empty" error
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_user_path_text(text, label="path")
    else:
        # Check if text contains control characters (ASCII < 32)
        # The implementation rejects ALL characters with ord < 32, including \t\n\r
        has_control = any(ord(ch) < 32 for ch in stripped)
        if has_control:
            with pytest.raises(ValueError, match="control characters"):
                validate_user_path_text(text, label="path")
        else:
            # Should not raise for valid text
            validate_user_path_text(text, label="path")


@settings(max_examples=100, phases=[Phase.generate])
@given(st.text(min_size=1))
def test_validate_relative_component_dots_rejected(text):
    """Property: validate_relative_component rejects '.' and '..'."""
    stripped = text.strip()
    if not stripped:
        # Empty strings raise "cannot be empty" error
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_relative_component(text, label="component")
    else:
        # Check for control characters first (ALL ASCII < 32 chars are rejected)
        has_control = any(ord(ch) < 32 for ch in stripped)
        if has_control:
            with pytest.raises(ValueError, match="control characters"):
                validate_relative_component(text, label="component")
        elif stripped in {".", ".."}:
            with pytest.raises(ValueError, match="cannot be '.' or '..'"):
                validate_relative_component(stripped, label="component")
        elif "/" in stripped or "\\" in stripped:
            with pytest.raises(ValueError, match="must not contain path separators"):
                validate_relative_component(stripped, label="component")
        else:
            # Should not raise for valid component
            result = validate_relative_component(stripped, label="component")
            assert result == stripped


@settings(max_examples=50, phases=[Phase.generate])
@given(st.builds(dict))
def test_ensure_child_path_resolves_within_base(path_dict):
    """Property: ensure_child_path ensures target is within base directory."""
    # This test is complex because we need to create actual paths
    # For property testing, we'll use a simpler approach with valid paths
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        # Create a subdirectory
        subdir = base / "subdir"
        subdir.mkdir()
        
        # Valid child path should work
        result = ensure_child_path(base, subdir, label="path")
        assert result == subdir.resolve()
        
        # Path outside base should raise
        outside = base.parent / "outside"
        with pytest.raises(ValueError, match="escapes the expected base directory"):
            ensure_child_path(base, outside, label="path")


@settings(max_examples=100, phases=[Phase.generate])
@given(st.text())
def test_validate_archive_member_absolute_rejected(member_name):
    """Property: validate_archive_member rejects absolute paths."""
    if member_name.startswith("/") or member_name.startswith("\\"):
        with pytest.raises(ValueError, match="Unsafe archive member path"):
            validate_archive_member(member_name)
    elif member_name:
        # May raise for other reasons, but not for absolute path
        try:
            result = validate_archive_member(member_name)
            # If it succeeds, should not be absolute
            assert not result.is_absolute()
        except ValueError as e:
            # Should be for other reasons, not absolute path
            assert "absolute" not in str(e).lower()


@settings(max_examples=100, phases=[Phase.generate])
@given(st.text())
def test_validate_archive_member_traversal_rejected(member_name):
    """Property: validate_archive_member rejects path traversal components."""
    stripped = member_name.strip()
    if not stripped:
        # Empty strings (including ".") raise "cannot be empty" error before traversal check
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_archive_member(member_name)
    elif ".." in member_name:
        with pytest.raises(ValueError, match="Unsafe archive member path"):
            validate_archive_member(member_name)
    elif member_name:
        # May raise for other reasons
        try:
            result = validate_archive_member(member_name)
            # If it succeeds, should not contain traversal
            assert ".." not in str(result)
            assert "" not in result.parts
        except ValueError:
            pass  # Expected for other invalid inputs


@settings(max_examples=50, phases=[Phase.generate])
@given(st.text())
def test_validate_archive_member_windows_drives_rejected(member_name):
    """Property: validate_archive_member rejects Windows drive letters."""
    # Check for Windows drive letter pattern (e.g., C:)
    if len(member_name) >= 2 and member_name[1] == ":" and member_name[0].isalpha():
        with pytest.raises(ValueError, match="Unsafe archive member path"):
            validate_archive_member(member_name)
