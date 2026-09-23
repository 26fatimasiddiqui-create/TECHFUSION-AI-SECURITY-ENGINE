import logging
from typing import Optional
from supabase import create_client, Client
from app.core.config import settings

logger = logging.getLogger(__name__)

_supabase_client: Optional[Client] = None


def get_supabase_client() -> Optional[Client]:
    """Returns the singleton Supabase client or initializes it if credentials are provided.
    Returns None if SUPABASE_URL or SUPABASE_KEY are not configured.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
        logger.warning("Supabase credentials not configured (SUPABASE_URL or SUPABASE_KEY is missing).")
        return None

    try:
        _supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
        logger.info("Supabase client successfully initialized.")
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None
