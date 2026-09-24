from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api import (
    events_router,
    analyze_router,
    incidents_router,
    alerts_router,
    n8n_router,
    users_router,
    response_router,
)

app = FastAPI(
    title="TechFusion — Autonomous AI Security & Risk Correlation Platform",
    description="Enterprise AI-assisted security event correlation, risk-adaptive response, and contextual threat detection API",
    version="1.0.0",
)

# Enable CORS for local testing, dashboards, and integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(events_router)
app.include_router(analyze_router)
app.include_router(incidents_router)
app.include_router(alerts_router)
app.include_router(n8n_router)
app.include_router(users_router)
app.include_router(response_router)


@app.get("/health", tags=["system"])
@app.get("/api/health", tags=["system"])
async def health_check():
    """Health check endpoint displaying system operational status and integrations."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "PS-8 Backend",
        "environment": settings.ENVIRONMENT,
        "integrations": {
            "supabase": bool(settings.SUPABASE_URL and settings.SUPABASE_KEY),
            "cognee": bool(settings.COGNEE_API_KEY),
            "n8n_webhook": bool(settings.N8N_WEBHOOK_URL),
        },
    }
