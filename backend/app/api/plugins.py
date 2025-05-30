"""
Plugins REST API

  GET    /api/plugins              — list all registered plugins
  GET    /api/plugins/{plugin_id}  — get plugin details
  POST   /api/plugins/install      — install (register+enable) an in-process plugin
  POST   /api/plugins/{plugin_id}/enable   — enable plugin
  POST   /api/plugins/{plugin_id}/disable  — disable plugin
  DELETE /api/plugins/{plugin_id}  — uninstall plugin
  GET    /api/plugins/{plugin_id}/health   — health check for one plugin
  GET    /api/plugins/health/all   — health check for all enabled plugins
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.plugins.plugin_manager import PluginManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/plugins", tags=["Plugins"])

# ---------------------------------------------------------------------------
# Singleton plugin manager (lazy init)
# ---------------------------------------------------------------------------

_plugin_manager: Optional[PluginManager] = None
_plugin_manager_lock = threading.Lock()


def _get_manager() -> PluginManager:
    global _plugin_manager
    if _plugin_manager is None:
        with _plugin_manager_lock:
            if _plugin_manager is None:
                _plugin_manager = PluginManager()
    return _plugin_manager


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class InstallPluginRequest(BaseModel):
    example: Optional[str] = None


class PluginResponse(BaseModel):
    plugin_id: str
    name: str
    version: str
    status: str
    description: str
    tags: List[str]
    author: str


class PluginListResponse(BaseModel):
    plugins: List[PluginResponse]
    total: int


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _to_plugin_response(info: Dict[str, Any]) -> PluginResponse:
    return PluginResponse(
        plugin_id=info["plugin_id"],
        name=info["name"],
        version=info["version"],
        status=info["status"],
        description=info["description"],
        tags=info.get("tags", []),
        author=info["author"],
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=PluginListResponse)
async def list_plugins() -> PluginListResponse:
    """List all registered plugins."""
    manager = _get_manager()
    plugins = manager.list_plugins()
    responses = [_to_plugin_response(p) for p in plugins]
    return PluginListResponse(plugins=responses, total=len(responses))


@router.get("/health/all", response_model=Dict[str, Any])
async def health_check_all() -> Dict[str, Any]:
    """Run health checks on all enabled plugins."""
    manager = _get_manager()
    return manager.health_check_all()


@router.get("/{plugin_id}", response_model=PluginResponse)
async def get_plugin(plugin_id: str) -> PluginResponse:
    """Get details for a specific plugin."""
    manager = _get_manager()
    info = manager.get_plugin_info(plugin_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found.")
    return _to_plugin_response(info)


@router.post("/install", response_model=PluginResponse, status_code=201)
async def install_plugin(request: InstallPluginRequest) -> PluginResponse:
    """
    Install an in-process plugin.

    Pass ``{"example": "shodan"}`` or ``{"example": "censys"}`` to install the
    built-in example plugins. This endpoint is designed for demo and testing
    purposes; production deployments can extend it to support pip-based installs.
    """
    manager = _get_manager()

    if request.example == "shodan":
        from app.plugins.examples.shodan_plugin import get_plugin
        plugin = get_plugin()
    elif request.example == "censys":
        from app.plugins.examples.censys_plugin import get_plugin
        plugin = get_plugin()
    else:
        raise HTTPException(
            status_code=422,
            detail=(
                "Unsupported example plugin. "
                "Currently supported: 'shodan', 'censys'."
            ),
        )

    try:
        pid = manager.install_plugin(plugin)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    info = manager.get_plugin_info(pid)
    return _to_plugin_response(info)


@router.post("/{plugin_id}/enable", response_model=PluginResponse)
async def enable_plugin(plugin_id: str) -> PluginResponse:
    """Enable a registered plugin."""
    manager = _get_manager()
    try:
        manager.enable_plugin(plugin_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found.")
    info = manager.get_plugin_info(plugin_id)
    return _to_plugin_response(info)


@router.post("/{plugin_id}/disable", response_model=PluginResponse)
async def disable_plugin(plugin_id: str) -> PluginResponse:
    """Disable a registered plugin."""
    manager = _get_manager()
    try:
        manager.disable_plugin(plugin_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found.")
    info = manager.get_plugin_info(plugin_id)
    return _to_plugin_response(info)


@router.delete("/{plugin_id}", status_code=204, response_model=None)
async def uninstall_plugin(plugin_id: str) -> None:
    """Uninstall (disable + unregister) a plugin."""
    manager = _get_manager()
    try:
        manager.uninstall_plugin(plugin_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found.")


@router.get("/{plugin_id}/health", response_model=Dict[str, Any])
async def plugin_health(plugin_id: str) -> Dict[str, Any]:
    """Run a health check for a specific plugin."""
    manager = _get_manager()
    plugin = manager.get_registry().get(plugin_id)
    if plugin is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found.")
    try:
        return plugin.health_check()
    except Exception as exc:
        return {"healthy": False, "error": str(exc)}
