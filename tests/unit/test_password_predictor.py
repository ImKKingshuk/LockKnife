import json
import pathlib

from lockknife.modules.ai.password_predictor import PasswordPredictor, load_personal_data


def test_password_predictor_generates(tmp_path: pathlib.Path) -> None:
    wl = tmp_path / "wl.txt"
    wl.write_text("password\npasscode\npass\n", encoding="utf-8")
    model = PasswordPredictor.train_from_wordlist(wl, max_words=10, order=2)
    personal = tmp_path / "person.json"
    personal.write_text(json.dumps({"owner": "Casey", "device": {"model": "Pixel8"}}), encoding="utf-8")
    out = model.generate(count=20, min_len=4, max_len=12, seed=0, personal_data=load_personal_data(personal))
    assert isinstance(out, list)
    assert any(item.lower().startswith("casey") or item.lower().startswith("pixel8") for item in out)
