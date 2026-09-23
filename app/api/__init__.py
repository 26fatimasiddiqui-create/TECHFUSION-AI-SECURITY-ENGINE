from app.api.events import router as events_router
from app.api.analyze import router as analyze_router
from app.api.incidents import router as incidents_router
from app.api.alerts import router as alerts_router
from app.api.n8n import router as n8n_router
from app.api.users import router as users_router
from app.api.response import router as response_router

__all__ = [
    "events_router",
    "analyze_router",
    "incidents_router",
    "alerts_router",
    "n8n_router",
    "users_router",
    "response_router",
]

