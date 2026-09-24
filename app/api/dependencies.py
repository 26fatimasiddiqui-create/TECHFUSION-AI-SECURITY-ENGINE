from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.alert_service import AlertService
from app.services.activity_graph_service import ActivityGraphService
from app.services.response_service import ResponseService
from app.services.agent_security_service import AgentSecurityService
from app.services.external_threat_service import ExternalThreatService
from app.repositories.supabase_repository import SupabaseRepository

supabase_repository = SupabaseRepository()
response_service = ResponseService(repo=supabase_repository)
detection_service = DetectionService()
correlation_service = CorrelationService()
cognee_service = CogneeService()
risk_service = RiskService()
agent_security_service = AgentSecurityService()
external_threat_service = ExternalThreatService()
alert_service = AlertService(repo=supabase_repository, response_svc=response_service, correlation_svc=correlation_service)
activity_graph_service = ActivityGraphService(
    repo=supabase_repository,
    detection_svc=detection_service,
    correlation_svc=correlation_service,
    cognee_svc=cognee_service,
    risk_svc=risk_service,
)


def get_detection_service() -> DetectionService:
    return detection_service


def get_correlation_service() -> CorrelationService:
    return correlation_service


def get_cognee_service() -> CogneeService:
    return cognee_service


def get_risk_service() -> RiskService:
    return risk_service


def get_agent_security_service() -> AgentSecurityService:
    return agent_security_service


def get_external_threat_service() -> ExternalThreatService:
    return external_threat_service


def get_alert_service() -> AlertService:
    return alert_service


def get_supabase_repository() -> SupabaseRepository:
    return supabase_repository


def get_activity_graph_service() -> ActivityGraphService:
    return activity_graph_service


def get_response_service() -> ResponseService:
    return response_service

