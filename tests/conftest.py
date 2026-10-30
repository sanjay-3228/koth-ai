"""Global pytest configuration for test isolation.
Guarantees that tests never write to or pollute the root koth_agent.db database.
"""
import os
import tempfile
import pytest

@pytest.fixture(autouse=True, scope="session")
def isolate_test_database():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        test_db = os.path.join(tmp_dir, "isolated_test_koth.db")
        old_db = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = test_db
        
        from agent.config import config
        config.db_path = test_db
        
        from agent.db import db
        db.db_path = test_db
        db._init_db()
        
        yield test_db
        
        if old_db is not None:
            os.environ["DB_PATH"] = old_db
        else:
            os.environ.pop("DB_PATH", None)


@pytest.fixture(autouse=True)
def reset_emergency_stop_state():
    from agent.db import db
    try:
        db.set_emergency_stop(active=False, actor="system", reason="test_reset")
    except Exception:
        pass
    yield
    try:
        db.set_emergency_stop(active=False, actor="system", reason="test_teardown")
    except Exception:
        pass
