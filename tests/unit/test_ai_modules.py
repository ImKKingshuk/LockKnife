import types


def test_password_predictor_generates(tmp_path) -> None:
    from lockknife.modules.ai.password_predictor import PasswordPredictor

    wl = tmp_path / "w.txt"
    wl.write_text("alpha\nbeta\n", encoding="utf-8")
    model = PasswordPredictor.train_from_wordlist(wl, max_words=10, order=2)
    out = model.generate(count=5, min_len=3, max_len=8, seed=1, personal_data={"owner": "Alice", "email": "alice@example.com"})
    assert all(3 <= len(x) <= 8 for x in out)
    assert any("Alice" in value or "alice" in value for value in out)


def test_anomaly_scores_with_fake_sklearn(monkeypatch) -> None:
    from lockknife.modules.ai import anomaly as anomaly_mod

    class _IF:
        def __init__(self, random_state: int, n_estimators: int, contamination: str) -> None:
            _ = (random_state, n_estimators, contamination)

        def fit(self, _x):
            return self

        def score_samples(self, x):
            return _Arr([-(idx + 1.0) for idx in range(len(x))])

    class _LOF:
        def __init__(self, n_neighbors: int, contamination: str) -> None:
            _ = (n_neighbors, contamination)
            self.negative_outlier_factor_ = _Arr([-2.0, -4.0])

        def fit(self, _x):
            return self

    class _Arr(list):
        def __neg__(self):
            return _Arr([-float(v) for v in self])

        def tolist(self):
            return list(self)

    fake_np = types.SimpleNamespace(array=lambda x, dtype=None: _Arr(x))
    fake_sklearn = types.SimpleNamespace(
        ensemble=types.SimpleNamespace(IsolationForest=_IF),
        neighbors=types.SimpleNamespace(LocalOutlierFactor=_LOF),
    )

    monkeypatch.setitem(__import__("sys").modules, "numpy", fake_np)
    monkeypatch.setitem(__import__("sys").modules, "sklearn", fake_sklearn)
    monkeypatch.setitem(__import__("sys").modules, "sklearn.ensemble", fake_sklearn.ensemble)
    monkeypatch.setitem(__import__("sys").modules, "sklearn.neighbors", fake_sklearn.neighbors)

    rows = [{"a": 1.0}, {"a": 2.0}]
    out = anomaly_mod.anomaly_scores(rows, ["a"])
    assert out[1]["anomaly_score"] == 1.0
    assert out[0]["models"]["isolation_forest"] == 0.0
    assert out[1]["explanation"]["top_features"][0]["feature"] == "a"


def test_malware_classifier_with_fake_sklearn(monkeypatch, tmp_path) -> None:
    from lockknife.modules.ai import malware_classifier as mc

    class _RF:
        def __init__(self, random_state: int, n_estimators: int) -> None:
            _ = (random_state, n_estimators)

        def fit(self, _x, _y):
            return self

        def predict(self, x):
            return _Arr([1 for _ in range(len(x))])

        def predict_proba(self, x):
            return _Arr([[0.1, 0.9] for _ in range(len(x))])

    class _Arr(list):
        def tolist(self):
            return list(self)

    fake_np = types.SimpleNamespace(array=lambda x, dtype=None: _Arr(x))
    store: dict[str, object] = {}

    class _Joblib:
        @staticmethod
        def dump(payload, path):
            store[path] = payload

        @staticmethod
        def load(path):
            return store[path]

    fake_sklearn = types.SimpleNamespace(ensemble=types.SimpleNamespace(RandomForestClassifier=_RF))

    monkeypatch.setitem(__import__("sys").modules, "numpy", fake_np)
    monkeypatch.setitem(__import__("sys").modules, "joblib", _Joblib)
    monkeypatch.setitem(__import__("sys").modules, "sklearn", fake_sklearn)
    monkeypatch.setitem(__import__("sys").modules, "sklearn.ensemble", fake_sklearn.ensemble)

    rows = [
        {"label": 1, "permissions": ["READ_SMS", "INTERNET"], "api_calls": ["Runtime.exec", "loadLibrary"]},
        {"label": 0, "permissions": ["INTERNET"], "api_calls": ["Log.d"]},
    ]
    model_path = tmp_path / "model.pkl"
    out_path = mc.train_classifier(rows, [], "label", model_path)
    assert out_path.exists() is True or str(out_path) in store
    preds = mc.predict_classifier(rows, model_path)
    assert preds[0]["prediction"] == 1
    assert preds[0]["confidence"] == 0.9
    assert "apk_permission_count" in preds[0]["feature_snapshot"]
