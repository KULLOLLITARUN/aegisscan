import pytest


@pytest.fixture(autouse=True)
def _isolated_history_db(tmp_path_factory, monkeypatch):
    """Keep the tests from writing scan history into the real AegisScan data folder."""
    monkeypatch.setenv("AEGISSCAN_HISTORY_DB", str(tmp_path_factory.mktemp("history") / "history.db"))
