from lockknife.modules.extraction.media import _parse_exif_gps


def test_parse_exif_gps_empty() -> None:
    assert _parse_exif_gps(b"") == (None, None)
