import json


def test_write_json_and_csv(tmp_path) -> None:
    from lockknife.core.serialize import write_csv, write_json

    jp = tmp_path / "a" / "x.json"
    write_json(jp, {"b": 2})
    assert json.loads(jp.read_text(encoding="utf-8")) == {"b": 2}

    cp = tmp_path / "a" / "x.csv"
    write_csv(cp, [{"a": 1, "b": 2}, {"b": 3}])
    text = cp.read_text(encoding="utf-8")
    assert "a" in text and "b" in text
