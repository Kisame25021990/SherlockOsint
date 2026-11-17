import os
import tempfile

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault(
    "OSINT_DB_PATH", os.path.join(tempfile.mkdtemp(prefix="sherlock-osint-tests-"), "test.db")
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
