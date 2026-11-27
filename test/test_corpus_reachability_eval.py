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
