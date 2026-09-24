import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx
from app.core.config import settings
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


class CogneeService:
    """Cognee contextual knowledge and relationship retrieval service.
    Tracks historical baseline relationships across agents, tools, users, devices, IPs,
    login schedules, roles, and geographic locations.
    Provides graceful offline fallback so the security pipeline never crashes.
    """

    KNOWN_LOCATIONS = {
        "delhi": (28.6139, 77.2090),
        "new delhi": (28.6139, 77.2090),
        "mumbai": (19.0760, 72.8777),
        "bangalore": (12.9716, 77.5946),
        "london": (51.5074, -0.1278),
        "new york": (40.7128, -74.0060),
        "singapore": (1.3521, 103.8198),
        "tokyo": (35.6762, 139.6503),
        "san francisco": (37.7749, -122.4194),
        "frankfurt": (50.1109, 8.6821),
    }

    def __init__(self):
        self.api_key = settings.COGNEE_API_KEY
        self.api_url = settings.COGNEE_API_URL or "https://api.cognee.ai"

        # Local contextual knowledge graph / baseline memory
        self._agent_known_tools: Dict[str, Set[str]] = {
            "agent_copilot": {"search_docs", "format_json", "read_summary"},
            "agent_support": {"lookup_ticket", "send_email"},
            "agent_analytics": {"generate_report", "aggregate_metrics"},
            "HR_Agent": {"lookup_employee", "view_org_chart", "generate_payroll_slip"},
        }
        self._user_known_devices: Dict[str, Set[str]] = {
            "U001": {"D001", "D002"},
            "admin_user": {"corporate_mac_01"},
            "A. Verma": {"Laptop (Windows)", "workstation_01"},
            "J. Singh": {"Laptop (Windows)", "corporate_laptop_js"},
            "R. Khan": {"workstation_rk", "dev_box_linux"},
        }
        self._user_known_ips: Dict[str, Set[str]] = {
            "U001": {"192.168.1.50", "10.0.0.1"},
            "admin_user": {"192.168.1.1", "10.0.0.5"},
            "A. Verma": {"192.168.1.10", "10.0.0.1"},
            "J. Singh": {"10.0.0.1", "192.168.1.25"},
            "R. Khan": {"10.0.0.2", "192.168.1.30"},
        }
        self._user_normal_hours: Dict[str, Tuple[int, int]] = {
            "U001": (8, 19),
            "admin_user": (7, 21),
            "A. Verma": (9, 18),
            "J. Singh": (9, 18),
            "R. Khan": (8, 19),
        }
        self._user_roles: Dict[str, str] = {
            "U001": "Analyst",
            "admin_user": "Administrator",
            "A. Verma": "Software Engineer",
            "J. Singh": "HR Specialist",
            "R. Khan": "Database Administrator",
        }
        self._role_allowed_resources: Dict[str, Set[str]] = {
            "HR Specialist": {"/api/v1/hr", "/api/hr", "/database/hr", "/api/v1/employees", "/api/v1/payroll/view"},
            "Software Engineer": {"/api/v1/repos", "/api/v1/builds", "/api/v1/dev", "/api/customer-data/read"},
            "Analyst": {"/api/v1/analytics", "/api/v1/reports", "/api/customer-data"},
            "Database Administrator": {"/database/customer_credentials/dump", "/database", "/admin", "/backup"},
            "Administrator": {"*"},
        }
        # Last known location per user: user_id -> {city, timestamp, lat, lon}
        self._user_last_locations: Dict[str, Dict[str, Any]] = {
            "U001": {
                "city": "delhi",
                "timestamp": datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc),
                "lat": 28.6139,
                "lon": 77.2090,
            },
            "J. Singh": {
                "city": "delhi",
                "timestamp": datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc),
                "lat": 28.6139,
                "lon": 77.2090,
            },
            "A. Verma": {
                "city": "bangalore",
                "timestamp": datetime(2026, 9, 22, 9, 0, tzinfo=timezone.utc),
                "lat": 12.9716,
                "lon": 77.5946,
            },
        }
        self._resolved_threat_users: Set[str] = set()

    async def get_historical_context(self, event: SecurityEvent) -> Dict[str, Any]:
        """Retrieves historical relationship context for the given event from Cognee
        (or resilient local knowledge graph fallback).
        """
        # If Cognee remote service is configured, attempt remote query
        if self.api_key:
            try:
                remote_context = await self._query_cognee_remote(event)
                if remote_context:
                    return remote_context
            except Exception as e:
                logger.warning(f"Cognee remote service error (falling back to baseline): {e}")

        # Fallback to local relationship baseline
        return self._evaluate_local_baseline(event)

    async def _query_cognee_remote(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Invokes Cognee API to inspect graph relationships for user, device, and agent."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "entity_id": event.agent_id or event.user_id or event.device_id,
            "action": event.event_type,
            "resource": event.resource,
            "tool": event.tool_name,
            "metadata": event.metadata,
        }
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{self.api_url}/api/v1/context/search",
                json=payload,
                headers=headers,
            )
            if resp.status_code == 200:
                return resp.json()
        return None

    def _calculate_haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculates great-circle distance between two points on Earth in km."""
        r = 6371.0  # Earth's radius in km
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        a = (
            math.sin(delta_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    def _get_coordinates(self, location_name: Optional[str], lat: Optional[float], lon: Optional[float]) -> Optional[Tuple[float, float]]:
        if lat is not None and lon is not None:
            return float(lat), float(lon)
        if location_name:
            loc_key = str(location_name).strip().lower()
            if loc_key in self.KNOWN_LOCATIONS:
                return self.KNOWN_LOCATIONS[loc_key]
        return None

    def _evaluate_local_baseline(self, event: SecurityEvent) -> Dict[str, Any]:
        """Local graph relationship evaluation comparing current behavior against baseline."""
        context_data: Dict[str, Any] = {
            "is_anomaly": False,
            "tool_never_used_by_agent": False,
            "device_unseen_for_user": False,
            "ip_unseen_for_user": False,
            "impossible_travel_suspected": False,
            "abnormal_login_time": False,
            "role_resource_mismatch": False,
            "summary": "Activity is consistent with historical entity baseline.",
            "historical_baseline": {},
        }
        # If user was explicitly approved/resolved by SOC analyst, treat as benign baseline
        if event.user_id and event.user_id in getattr(self, "_resolved_threat_users", set()):
            context_data["is_anomaly"] = False
            context_data["summary"] = f"Activity verified and approved for user '{event.user_id}'. Cognee baseline cleared."
            return context_data

        reasons_found: List[str] = []

        # 1. Agent -> Tool historical relationship
        if event.agent_id and event.tool_name:
            known_tools = self._agent_known_tools.get(event.agent_id)
            context_data["historical_baseline"]["agent_id"] = event.agent_id
            if known_tools is not None:
                context_data["historical_baseline"]["normal_tools"] = sorted(list(known_tools))
                if event.tool_name not in known_tools:
                    context_data["is_anomaly"] = True
                    context_data["tool_never_used_by_agent"] = True
                    reasons_found.append(
                        f"Agent '{event.agent_id}' normally uses {sorted(list(known_tools))}. "
                        f"Tool '{event.tool_name}' has never previously been used by this agent."
                    )
            else:
                context_data["historical_baseline"]["normal_tools"] = []

        # 2. User -> Device historical relationship
        if event.user_id and event.device_id:
            known_devices = self._user_known_devices.get(event.user_id)
            context_data["historical_baseline"]["user_id"] = event.user_id
            if known_devices is not None:
                context_data["historical_baseline"]["normal_devices"] = sorted(list(known_devices))
                if event.device_id not in known_devices:
                    context_data["is_anomaly"] = True
                    context_data["device_unseen_for_user"] = True
                    reasons_found.append(
                        f"User '{event.user_id}' known devices are {sorted(list(known_devices))}. "
                        f"Device '{event.device_id}' is unrecorded in user's historical profile."
                    )
            else:
                context_data["historical_baseline"]["normal_devices"] = []

        # 3. User -> IP Address historical relationship
        ip_val = (
            event.metadata.get("ip")
            or event.metadata.get("ip_address")
            or event.metadata.get("client_ip")
            or event.metadata.get("source_ip")
        )
        if event.user_id and ip_val:
            known_ips = self._user_known_ips.get(event.user_id)
            if known_ips is not None:
                context_data["historical_baseline"]["normal_ips"] = sorted(list(known_ips))
                if str(ip_val).strip() not in known_ips:
                    context_data["is_anomaly"] = True
                    context_data["ip_unseen_for_user"] = True
                    reasons_found.append(
                        f"IP '{ip_val}' is not normally associated with user '{event.user_id}'."
                    )
            else:
                context_data["historical_baseline"]["normal_ips"] = []

        # 4. User -> Normal Login/Activity Hours
        if event.user_id and event.user_id in self._user_normal_hours:
            normal_hours = self._user_normal_hours[event.user_id]
            context_data["historical_baseline"]["normal_hours"] = normal_hours
            event_hour = event.timestamp.hour
            if event_hour < normal_hours[0] or event_hour >= normal_hours[1]:
                # If explicit override not marked as normal
                if event.metadata.get("is_abnormal_time") is not False:
                    context_data["is_anomaly"] = True
                    context_data["abnormal_login_time"] = True
                    reasons_found.append(
                        f"Activity at {event_hour:02d}:00 UTC is outside user's normal baseline hours ({normal_hours[0]:02d}:00 - {normal_hours[1]:02d}:00)."
                    )

        # 5. User -> Impossible Travel (Speed / Distance check)
        loc_val = event.metadata.get("location") or event.metadata.get("city")
        lat_val = event.metadata.get("lat") or event.metadata.get("latitude")
        lon_val = event.metadata.get("lon") or event.metadata.get("longitude")
        curr_coords = self._get_coordinates(loc_val, lat_val, lon_val)

        if event.user_id and curr_coords:
            last_loc = self._user_last_locations.get(event.user_id)
            if last_loc:
                prev_coords = (last_loc["lat"], last_loc["lon"])
                prev_time = last_loc["timestamp"]
                curr_time = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
                if prev_time.tzinfo is None:
                    prev_time = prev_time.replace(tzinfo=timezone.utc)
                
                time_delta_seconds = abs((curr_time - prev_time).total_seconds())
                time_delta_hours = max(time_delta_seconds / 3600.0, 0.001)

                distance_km = self._calculate_haversine_distance(
                    prev_coords[0], prev_coords[1], curr_coords[0], curr_coords[1]
                )

                # Flag impossible travel if calculated speed exceeds 850 km/h and distance is meaningful (> 250 km)
                # or if distant cities (> 1000 km) within unrealistic time window (< 1.5 hours)
                if distance_km > 250:
                    speed_kmh = distance_km / time_delta_hours
                    if speed_kmh > 850 or (distance_km > 1000 and time_delta_hours < 2.0):
                        context_data["is_anomaly"] = True
                        context_data["impossible_travel_suspected"] = True
                        reasons_found.append(
                            f"Impossible travel detected: User moved {int(distance_km)} km ({last_loc.get('city', 'previous location')} -> {loc_val or 'new location'}) in {time_delta_hours:.2f} hours (~{int(speed_kmh)} km/h)."
                        )

        # 6. User -> Role and Resource Access Baseline
        if event.user_id and event.resource:
            user_role = self._user_roles.get(event.user_id)
            if user_role:
                context_data["historical_baseline"]["user_role"] = user_role
                allowed = self._role_allowed_resources.get(user_role, set())
                if "*" not in allowed:
                    res_path = event.resource.lower()
                    is_match = any(allowed_res.lower() in res_path for allowed_res in allowed)
                    if not is_match and (
                        "admin" in res_path
                        or "credential" in res_path
                        or "export" in res_path
                        or "dump" in res_path
                        or "payroll" in res_path
                        or "secret" in res_path
                    ):
                        context_data["is_anomaly"] = True
                        context_data["role_resource_mismatch"] = True
                        reasons_found.append(
                            f"User '{event.user_id}' with role '{user_role}' accessed unusual high-sensitivity resource '{event.resource}' outside normal role profile."
                        )

        if reasons_found:
            context_data["summary"] = " | ".join(reasons_found)

        return context_data

    async def store_event_context(self, event: SecurityEvent) -> None:
        """Stores or associates the event into memory/graph for baseline modeling."""
        try:
            if event.agent_id and event.tool_name:
                self._agent_known_tools.setdefault(event.agent_id, set()).add(event.tool_name)
            if event.user_id and event.device_id:
                self._user_known_devices.setdefault(event.user_id, set()).add(event.device_id)

            ip_val = (
                event.metadata.get("ip")
                or event.metadata.get("ip_address")
                or event.metadata.get("client_ip")
                or event.metadata.get("source_ip")
            )
            if event.user_id and ip_val:
                self._user_known_ips.setdefault(event.user_id, set()).add(str(ip_val).strip())

            # Update last location
            loc_val = event.metadata.get("location") or event.metadata.get("city")
            lat_val = event.metadata.get("lat") or event.metadata.get("latitude")
            lon_val = event.metadata.get("lon") or event.metadata.get("longitude")
            coords = self._get_coordinates(loc_val, lat_val, lon_val)
            if event.user_id and coords:
                now_ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
                self._user_last_locations[event.user_id] = {
                    "city": str(loc_val or "unknown").lower(),
                    "timestamp": now_ts,
                    "lat": coords[0],
                    "lon": coords[1],
                }
        except Exception as e:
            logger.warning(f"Failed to record context into Cognee cache: {e}")

    async def resolve_user_threats(
        self,
        user_id: str,
        device_id: Optional[str] = None,
        ip: Optional[str] = None,
        resource: Optional[str] = None,
        reason: str = "Analyst dual-control approval & baseline sync",
    ) -> Dict[str, Any]:
        """Synchronizes Cognee knowledge graph baseline upon analyst approval.
        Clears threat context, whitelists accessed devices/IPs/resources, and establishes
        a benign operational baseline for the user.
        """
        if not user_id:
            return {"status": "skipped", "reason": "No user_id provided"}

        if not hasattr(self, "_resolved_threat_users"):
            self._resolved_threat_users = set()
        self._resolved_threat_users.add(user_id)

        # Whitelist device in user's profile
        if device_id:
            self._user_known_devices.setdefault(user_id, set()).add(device_id)

        # Whitelist IP in user's profile
        if ip:
            self._user_known_ips.setdefault(user_id, set()).add(str(ip).strip())

        # Whitelist resource into role or user profile
        if resource:
            user_role = self._user_roles.get(user_id, "Analyst")
            self._role_allowed_resources.setdefault(user_role, set()).add(resource.lower())

        # Reset location timestamp so impossible travel checks don't mismatch
        if user_id in self._user_last_locations:
            self._user_last_locations[user_id]["timestamp"] = datetime.now(timezone.utc)

        # Remote Cognee sync if configured
        if self.api_key:
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "entity_id": user_id,
                    "action": "WHITELIST_BASELINE",
                    "reason": reason,
                    "metadata": {
                        "device_id": device_id,
                        "ip": ip,
                        "resource": resource,
                        "cleared_at": datetime.now(timezone.utc).isoformat(),
                    }
                }
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(
                        f"{self.api_url}/api/v1/context/whitelist",
                        json=payload,
                        headers=headers,
                    )
            except Exception as e:
                logger.warning(f"Cognee remote whitelist update error: {e}")

        logger.info(f"Cognee baseline synchronized and threat context cleared for user '{user_id}'.")
        return {
            "status": "success",
            "user_id": user_id,
            "cognee_baseline_updated": True,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

