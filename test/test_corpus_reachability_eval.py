"""The labelled mode and exit codes of contrib/reachability_eval.py."""

from contrib import reachability_eval


def test_every_item_erroring_exits_1(tmp_path, capsys):
    rc = reachability_eval.main(["--items", "py-vulpy", "--scan-dir", str(tmp_path / "missing")])
    assert rc == 1
    out = capsys.readouterr()
    assert "no scan directory" in out.out
    assert "nothing was scored" in out.err


def test_snapshot_options_select_the_snapshot_mode(capsys):
    # --snapshot without --check-snapshot used to fall through to the
    # labelled score and exit 0 having written nothing.
    assert reachability_eval.main(["--snapshot"]) == 2
    assert "Snapshot mode needs" in capsys.readouterr().err
    assert reachability_eval.main(["--check"]) == 2


def test_check_snapshot_compares_with_the_baseline(tmp_path, monkeypatch, capsys):
    import json

    baseline = tmp_path / "baseline.json"
    monkeypatch.setattr(reachability_eval, "BASELINE_FILE", str(baseline))
    repo = tmp_path / "repo"
    (repo / "reports").mkdir(parents=True)
    assert reachability_eval.main(["--check-snapshot", str(repo)]) == 2
    assert "No baseline" in capsys.readouterr().err
    assert reachability_eval.main(["--snapshot", str(repo)]) == 0
    assert reachability_eval.main(["--check-snapshot", str(repo)]) == 0
    recorded = json.loads(baseline.read_text(encoding="utf-8"))
    recorded[str(repo)]["SemanticReachability"]["sets"]["reached_purls"] = ["pkg:npm/x@1"]
    baseline.write_text(json.dumps(recorded), encoding="utf-8")
    assert reachability_eval.main(["--check-snapshot", str(repo)]) == 1
    assert "DIFFER" in capsys.readouterr().err


def test_unknown_items_exit_2(tmp_path, capsys):
    argv = ["--items", "py-vulpy,nope", "--scan-dir", str(tmp_path)]
    assert reachability_eval.main(argv) == 2
    assert "no item named: nope" in capsys.readouterr().err
