# UniVex Plugin Development Guide

> **Version:** 1.0  
> **Audience:** Plugin developers, security researchers, community contributors

---

## 1. Introduction

UniVex's plugin architecture lets you extend the platform with custom tools, MCP servers, and API routes — without touching core code. Plugins are self-contained Python packages discovered and loaded at runtime.

**What a plugin can provide:**

| Capability | API | Description |
|---|---|---|
| **Agent Tools** | `register_tools()` | `BaseTool` subclasses the AI agent can call |
| **MCP Servers** | `register_mcp_servers()` | External tool servers (Naabu, custom scanners …) |
| **API Routes** | `register_api_routes()` | FastAPI `APIRouter` instances mounted into the main app |

---

## 2. Plugin Structure

Each plugin is a Python package directory placed under `<repo_root>/plugins/`:

```
plugins/
 my_scanner/
     plugin.yaml       # required: manifest
     __init__.py       # required: must define get_plugin()
     tools.py          # optional: tool implementations
```

### `plugin.yaml` format

```yaml
name: my-scanner
version: 1.0.0
description: Custom network scanner plugin for UniVex
author: Your Name
license: MIT                   # optional, default MIT
min_univex_version: 1.0.0      # optional
tags:
  - recon
  - network
homepage: https://github.com/you/my-scanner  # optional
dependencies:                  # optional Python package requirements
  - httpx>=0.24
```

### `__init__.py` requirements

The `__init__.py` must expose a `get_plugin()` factory function that returns an instance of your `BasePlugin` subclass:

```python
from my_scanner.plugin import MyScanner

def get_plugin():
    return MyScanner()
```

---

## 3. BasePlugin Interface

All plugins must subclass `app.plugins.base_plugin.BasePlugin`.

```python
from app.plugins.base_plugin import BasePlugin, PluginManifest

class MyPlugin(BasePlugin):
    ...
```

### Required abstract members

| Member | Type | Description |
|---|---|---|
| `manifest` | property → `PluginManifest` | Plugin metadata |
| `register_tools()` | method → `List[BaseTool]` | Agent tools provided |
| `register_mcp_servers()` | method → `List[dict]` | MCP server configs |
| `register_api_routes()` | method → `List[APIRouter]` | FastAPI routers |

### Optional lifecycle hooks

| Hook | When called |
|---|---|
| `on_load()` | After successful registration in the registry |
| `on_unload()` | Before removal from the registry |
| `on_enable()` | When the plugin is enabled |
| `on_disable()` | When the plugin is disabled |

### Helpers

| Method | Returns | Description |
|---|---|---|
| `plugin_id` | `str` | Unique ID (`name-version`) |
| `get_info()` | `PluginInfo` | Snapshot of manifest + status |
| `health_check()` | `dict` | Override for custom health logic |

---

## 4. Creating Your First Plugin — Step-by-Step

### Step 1: Create the directory

```bash
mkdir -p plugins/hello_world
```

### Step 2: Write `plugin.yaml`

```yaml
name: hello-world
version: 1.0.0
description: A minimal example plugin
author: Alice Developer
tags: [example]
```

### Step 3: Implement the plugin

**`plugins/hello_world/tools.py`**

```python
from app.agent.tools.base_tool import BaseTool, ToolMetadata

class HelloTool(BaseTool):
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="hello_world",
            description="Returns a greeting for the given name.",
            parameters={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name to greet"}
                },
                "required": ["name"],
            },
        )

    async def execute(self, **kwargs) -> str:
        name = kwargs.get("name", "World")
        return f"Hello, {name}!"
```

**`plugins/hello_world/__init__.py`**

```python
from app.plugins.base_plugin import BasePlugin, PluginManifest
from hello_world.tools import HelloTool

class HelloWorldPlugin(BasePlugin):

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            name="hello-world",
            version="1.0.0",
            description="A minimal example plugin",
            author="Alice Developer",
            tags=["example"],
        )

    def register_tools(self):
        return [HelloTool()]

    def register_mcp_servers(self):
        return []

    def register_api_routes(self):
        return []

    def health_check(self):
        return {"healthy": True, "message": "Hello World plugin is ready"}


def get_plugin():
    return HelloWorldPlugin()
```

### Step 4: Install via the API

```bash
# The plugin will be auto-discovered on next startup, or install inline:
curl -X POST http://localhost:8000/api/plugins/install \
     -H "Content-Type: application/json" \
     -d '{"example": "hello-world"}'
```

---

## 5. Plugin Manifest Reference

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string |  | — | Unique plugin identifier (kebab-case) |
| `version` | string |  | — | Semantic version `x.y.z` |
| `description` | string |  | — | One-line human-readable description |
| `author` | string |  | — | Author name or GitHub handle |
| `license` | string |  | `MIT` | SPDX license identifier |
| `min_univex_version` | string |  | `1.0.0` | Minimum required UniVex version |
| `tags` | list[string] |  | `[]` | Searchable tags (recon, osint, exploit …) |
| `homepage` | string |  | `""` | Project URL |
| `dependencies` | list[string] |  | `[]` | pip-style requirements |

---

## 6. Tool Development

Tools are the primary way plugins extend UniVex's AI agent capabilities.

### Anatomy of a BaseTool

```python
from app.agent.tools.base_tool import BaseTool, ToolMetadata

class MyTool(BaseTool):

    def _define_metadata(self) -> ToolMetadata:
        """Called once in __init__. Describe your tool here."""
        return ToolMetadata(
            name="my_tool",                        # must be unique
            description="What this tool does",     # shown to the LLM
            parameters={                           # JSON Schema
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                },
                "required": ["target"],
            },
        )

    async def execute(self, **kwargs) -> str:
        """
        Tool logic. Must be async. Must return a string.
        The string is injected into the LLM's context window as an observation.
        """
        target = kwargs["target"]
        # ... perform the scan / lookup ...
        return f"Results for {target}: ..."
```

### Best practices

- **Always async.** `execute()` is `async def`.
- **Return a string.** The output is truncated to fit the context window.
- **Be idempotent.** The agent may retry failed tool calls.
- **Handle exceptions gracefully.** Return an error string rather than raising.
- **Respect rate limits.** Use exponential backoff for external APIs.

---

## 7. Security Model

UniVex uses an advisory-level security model via `SandboxedRunner`:

```

  Plugin Tool Execution                                   
                                                          
        
    Tool.execute  SandboxedRunner.run()          
        • Timeout: max_cpu_seconds      
                        • Thread-based isolation        
                        • Network CIDR check            
                        • Filesystem path check         
                        • Full audit log                
                        

```

### What is enforced

| Constraint | Default | Notes |
|---|---|---|
| CPU time limit | 30 s | Configurable via `SandboxConfig.max_cpu_seconds` |
| Thread timeout | Same as CPU limit | Thread is joined with timeout |
| Filesystem writes | Denied | Only `/tmp/univex-sandbox/` is writable |
| Network CIDR | `0.0.0.0/0` (all) | Restrict to target CIDR in production |
| Audit log | Enabled | All actions recorded with timestamp |

### What is NOT OS-enforced

The sandbox uses **advisory checks** (Python-level), not OS-level `seccomp` or `cgroups`. This is intentional — operators are trusted, and OS sandboxing would complicate deployment. For untrusted community plugins, run UniVex inside a container with appropriate Linux security profiles.

### `SandboxConfig` options

```python
from app.plugins.sandboxed_runner import SandboxConfig

config = SandboxConfig(
    allowed_target_cidr="10.10.10.0/24",  # restrict network
    max_cpu_seconds=10.0,
    max_memory_mb=128.0,
    sandbox_dir="/tmp/univex-sandbox",
    allow_network=True,
    allow_filesystem_read=True,
    allow_filesystem_write=False,
    audit_log=True,
)
```

---

## 8. Testing Your Plugin

### Unit tests

```python
import pytest
from my_scanner import get_plugin

def test_manifest():
    p = get_plugin()
    assert p.manifest.name == "my-scanner"
    assert p.manifest.version == "1.0.0"

def test_tools_non_empty():
    p = get_plugin()
    assert len(p.register_tools()) > 0

@pytest.mark.asyncio
async def test_tool_execute():
    from my_scanner.tools import MyScanTool
    tool = MyScanTool()
    result = await tool.execute(target="127.0.0.1")
    assert isinstance(result, str)
```

### Integration with PluginManager

```python
from app.plugins.plugin_manager import PluginManager
from my_scanner import get_plugin

def test_install_and_run():
    manager = PluginManager(plugins_dir="/tmp/empty")
    plugin = get_plugin()
    pid = manager.install_plugin(plugin)
    result = manager.run_plugin_tool(pid, "my_scan_tool", {"target": "127.0.0.1"})
    assert result.success
```

### Running the UniVex plugin test suite

```bash
cd backend
python -m pytest tests/test_plugin_system.py -v
```

---

## 9. Publishing Your Plugin

### GitHub repository

1. Name your repo `univex-plugin-<name>` (e.g. `univex-plugin-shodan`).
2. Include `plugin.yaml` at the root or in a `plugin/` subdirectory.
3. Add `univex-plugin` and relevant security topics.
4. Document required environment variables (API keys, etc.) in `README.md`.

### pip package

```
univex-plugin-<name>/
 plugin.yaml
 __init__.py
 tools.py
 setup.py (or pyproject.toml)
 README.md
```

`pyproject.toml` entry point:

```toml
[project.entry-points."univex.plugins"]
my_plugin = "univex_plugin_myname:get_plugin"
```

UniVex will automatically discover pip-installed plugins via entry points in a future release.

### Quality checklist

- [ ] `validate_manifest()` returns no errors
- [ ] All abstract methods implemented
- [ ] `health_check()` returns meaningful status
- [ ] No secrets committed to source
- [ ] Tests covering all tools
- [ ] `README.md` documents configuration requirements

---

## 10. Example Plugins Reference

### Shodan Plugin (`shodan`)

| Field | Value |
|---|---|
| Name | `shodan` |
| Version | `1.0.0` |
| Tags | `recon`, `osint`, `shodan` |
| Author | UniVex Community |
| Tools | `shodan_search`, `shodan_host_lookup` |
| MCP server | `localhost:9100` |
| Required config | `SHODAN_API_KEY` |

**Install:**

```bash
curl -X POST http://localhost:8000/api/plugins/install \
     -d '{"example": "shodan"}'
```

---

### Censys Plugin (`censys`)

| Field | Value |
|---|---|
| Name | `censys` |
| Version | `1.0.0` |
| Tags | `recon`, `osint`, `censys` |
| Author | UniVex Community |
| Tools | `censys_search`, `censys_certs` |
| MCP server | `localhost:9101` |
| Required config | `CENSYS_API_ID`, `CENSYS_API_SECRET` |

**Install:**

```bash
curl -X POST http://localhost:8000/api/plugins/install \
     -d '{"example": "censys"}'
```

---

## Appendix: REST API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/plugins` | List all plugins |
| `GET` | `/api/plugins/{id}` | Get plugin details |
| `POST` | `/api/plugins/install` | Install a plugin |
| `POST` | `/api/plugins/{id}/enable` | Enable a plugin |
| `POST` | `/api/plugins/{id}/disable` | Disable a plugin |
| `DELETE` | `/api/plugins/{id}` | Uninstall a plugin |
| `GET` | `/api/plugins/{id}/health` | Health check for one plugin |
| `GET` | `/api/plugins/health/all` | Health check for all enabled plugins |
