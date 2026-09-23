import pytest
from starlette.testclient import TestClient
from app.main import app
from app.api.dependencies import (
    get_detection_service,
    get_correlation_service,
    get_cognee_service,
    get_risk_service,
    get_alert_service,
    get_supabase_repository,
)
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.alert_service import AlertService
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def client():
    # Fresh isolated instances per test session
    return TestClient(app)


@pytest.fixture
def detection_svc():
    return DetectionService()


@pytest.fixture
def correlation_svc():
    return CorrelationService(time_window_minutes=30)


@pytest.fixture
def cognee_svc():
    return CogneeService()


@pytest.fixture
def risk_svc():
    return RiskService()


@pytest.fixture
def alert_svc():
    return AlertService(threshold=70)


@pytest.fixture
def repo():
    return SupabaseRepository()
