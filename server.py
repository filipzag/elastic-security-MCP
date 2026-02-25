from fastmcp import FastMCP
import requests
import os
import json
from dotenv import load_dotenv
import argparse
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
import asyncio

# Load environment variables
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("elastic-security")

def _make_request(method, endpoint, json_data=None, params=None):
    """
    Helper function to make authenticated requests to Kibana.
    """
    kibana_url = os.getenv("KIBANA_URL")
    api_key = os.getenv("ELASTIC_API_KEY")
    username = os.getenv("ELASTIC_USERNAME")
    password = os.getenv("ELASTIC_PASSWORD")

    if not kibana_url:
        return {"error": "KIBANA_URL environment variable is not set"}

    # Remove trailing slash from KIBANA_URL if present
    kibana_url = kibana_url.rstrip("/")
    # Ensure endpoint starts with slash
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
        
    url = f"{kibana_url}{endpoint}"

    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }

    auth = None
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username and password:
        auth = (username, password)
    else:
        return {"error": "ELASTIC_API_KEY or ELASTIC_USERNAME/ELASTIC_PASSWORD must be set"}

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            auth=auth,
            json=json_data,
            params=params,
            timeout=30
        )
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            return {
                "error": str(e),
                "status_code": response.status_code,
                "response_text": response.text
            }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def _list_rules(limit: int = 20, page: int = 1, filter: str = None):
    endpoint = "/api/detection_engine/rules/_find"
    params = {
        "per_page": limit,
        "page": page
    }
    if filter:
        params["filter"] = filter
    return _make_request("GET", endpoint, params=params)

@mcp.tool()
def list_rules(filter: str = None):
    """
    List all detection rules from Elastic Security. This will automatically paginate and return all matching rules.
    
    Args:
        filter: Optional KQL string to filter rules. The available fields for this filter include:
                - alert.attributes.name
                - alert.attributes.enabled
                - alert.attributes.tags
                - alert.attributes.createdBy
                - alert.attributes.interval
                - alert.attributes.updatedBy
                Example: 'alert.attributes.enabled: true' or 'alert.attributes.name: "My Rule"'
    """
    all_rules = []
    page = 1
    limit = 100  # Fetch 100 per page to minimize API calls
    
    while True:
        response = _list_rules(limit, page, filter)
        
        if "error" in response:
            if all_rules:
                return {"data": all_rules, "error": response["error"], "warning": "Failed while fetching subsequent pages"}
            return response
            
        data = response.get("data", [])
        all_rules.extend(data)
        
        total = response.get("total", 0)
        
        # Stop fetching if no more data is returned or we've reached the total
        if not data or len(all_rules) >= total:
            break
            
        page += 1
        
    return {"data": all_rules, "total": len(all_rules)}

def _upload_rule(rule_content: str):
    try:
        data = json.loads(rule_content)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON content: {str(e)}"}
        
    endpoint = "/api/detection_engine/rules"
    rule_id = data.get("id")
    method = "PUT" if rule_id else "POST"
        
    return _make_request(method, endpoint, json_data=data)

@mcp.tool()
def upload_rule(rule_content: str):
    """
    Upload (create or update) a new detection rule.
    
    Args:
        rule_content: The JSON string content of the rule to create or update.
    """
    return _upload_rule(rule_content)

def _enable_rule(rule_id: str):
    endpoint = "/api/detection_engine/rules"
    data = {"id": rule_id, "enabled": True}
    return _make_request("PATCH", endpoint, json_data=data)

@mcp.tool()
def enable_rule(rule_id: str):
    """
    Enable a detection rule by its ID.
    
    Args:
        rule_id: The unique identifier of the rule (id).
    """
    return _enable_rule(rule_id)

def _disable_rule(rule_id: str):
    endpoint = "/api/detection_engine/rules"
    data = {"id": rule_id, "enabled": False}
    return _make_request("PATCH", endpoint, json_data=data)

@mcp.tool()
def disable_rule(rule_id: str):
    """
    Disable a detection rule by its ID.
    
    Args:
        rule_id: The unique identifier of the rule (id).
    """
    return _disable_rule(rule_id)

@mcp.tool()
def get_detection_template() -> dict:
    """
    Returns a predefined Elastic detection rule JSON template for use.
    The template contains default tags, schedule, params, threat mapping, and an EQL query example.
    """
    return {
        "id": "98ec5b9d-e9f6-4f6a-a159-a37e9ba86cef",
        "enabled": True,
        "name": "APT28 Linux Timestomping via Touch Command",
        "tags": [
            "Domain: Endpoint",
            "OS: Linux",
            "Use Case: Threat Detection",
            "Tactic: Defense Evasion",
            "Data Source: Elastic Defend",
            "Threat: APT28"
        ],
        "rule_type_id": "siem.eqlRule",
        "consumer": "siem",
        "schedule": {"interval": "5m"},
        "actions": [],
        "params": {
            "author": ["AI Detection Engineering"],
            "description": "Detects potential timestomping activity on Linux systems. APT28 (Forest Blizzard/Fancy Bear) is known to use the touch command with -t, -r, or -d flags to alter file timestamps, making malicious files appear older or match legitimate system files. This technique (T1070.006) is used to evade forensic analysis and timeline reconstruction.",
            "note": "## Triage and Analysis\n\nTimestomping is a defense evasion technique where adversaries modify file timestamps. APT28 uses this on compromised Linux hosts after deploying tools like Drovorub or web shells.\n\n### Key Investigation Steps\n1. Examine touch command arguments for suspicious timestamps.\n2. Identify the target file path.\n3. Check parent process chain.\n4. Look for other APT28 indicators.\n5. Check user context.",
            "falsePositives": [
                "Build systems (make, cmake) frequently use touch to manage file timestamps.",
                "Package managers (dpkg, rpm, yum, apt-get) may use touch during installation.",
                "Configuration management tools (Ansible, Puppet, Chef, Salt) may touch files.",
                "EC2 network configuration scripts that use touch on systemd network files."
            ],
            "from": "now-6m",
            "ruleId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "immutable": False,
            "license": "Elastic License v2",
            "outputIndex": "",
            "maxSignals": 100,
            "riskScore": 47,
            "riskScoreMapping": [],
            "severity": "medium",
            "severityMapping": [],
            "timestampOverride": "event.ingested",
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0005",
                        "name": "Defense Evasion",
                        "reference": "https://attack.mitre.org/tactics/TA0005/"
                    },
                    "technique": [
                        {
                            "id": "T1070",
                            "name": "Indicator Removal",
                            "reference": "https://attack.mitre.org/techniques/T1070/",
                            "subtechnique": [
                                {
                                    "id": "T1070.006",
                                    "name": "Timestomp",
                                    "reference": "https://attack.mitre.org/techniques/T1070/006/"
                                }
                            ]
                        }
                    ]
                }
            ],
            "to": "now",
            "references": [],
            "version": 1,
            "exceptionsList": [],
            "relatedIntegrations": [],
            "requiredFields": [],
            "setup": "",
            "type": "eql",
            "language": "eql",
            "index": ["logs-endpoint.events.process-*"],
            "query": "process where host.os.type == \"linux\" and event.type == \"start\" and event.action == \"exec\" and process.name == \"touch\" and process.args in (\"-t\", \"-r\", \"-d\") and not process.parent.executable in (\"/usr/bin/make\", \"/usr/bin/cmake\", \"/usr/bin/dpkg\", \"/usr/bin/rpm\", \"/usr/bin/yum\", \"/usr/bin/apt-get\", \"/usr/bin/dnf\", \"/usr/bin/pip\", \"/usr/bin/pip3\", \"/usr/bin/conda\", \"/usr/lib/systemd/systemd\", \"/usr/bin/ansible-playbook\", \"/usr/bin/puppet\", \"/usr/bin/chef-client\", \"/opt/chef/bin/chef-client\", \"/usr/bin/salt-minion\") and not process.parent.name in (\"make\", \"cmake\", \"dpkg\", \"rpm\", \"yum\", \"apt-get\", \"dnf\") and not process.command_line like \"*ec2net_alias*\""
        },
        "mapped_params": {
            "risk_score": 47,
            "severity": "40-medium"
        },
        "scheduled_task_id": "98ec5b9d-e9f6-4f6a-a159-a37e9ba86cef",
        "created_by": "2637252352",
        "updated_by": "2637252352",
        "created_at": "2026-02-24T16:24:09.348Z",
        "updated_at": "2026-02-24T16:24:09.348Z",
        "api_key_owner": "2637252352",
        "api_key_created_by_user": True,
        "throttle": None,
        "mute_all": False,
        "notify_when": None,
        "muted_alert_ids": [],
        "execution_status": {
            "status": "pending",
            "last_execution_date": "2026-02-24T16:24:09.348Z"
        },
        "revision": 0,
        "running": False
    }

import argparse
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, auth_token: str):
        super().__init__(app)
        self.auth_token = auth_token

    async def dispatch(self, request: Request, call_next):
        # Allow health checks or other public endpoints if needed, but for now secure everything
        # specific to MCP endpoints often /sse or /messages
        
        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
        
        token = auth_header.split(" ")[1]
        if token != self.auth_token:
            return JSONResponse({"error": "Invalid token"}, status_code=403)
            
        return await call_next(request)

# ... (Helper functions and tools remain the same) ...

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Elastic Security MCP Server")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"], help="Transport protocol to use")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to for HTTP/SSE")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to for HTTP/SSE")
    parser.add_argument("--auth-token", help="Bearer token for authentication")
    
    args = parser.parse_args()
    
    # Check env var for auth token if not provided via CLI
    auth_token = args.auth_token or os.getenv("MCP_AUTH_TOKEN")
    
    kwargs = {}
    if args.transport in ["sse", "streamable-http"]:
        kwargs["port"] = args.port
        kwargs["host"] = args.host
        
        if auth_token:
            # Create middleware list with our auth middleware
            # We need to wrap it specifically for Starlette/FastAPI which FastMCP uses
            # FastMCP's run methods accept 'middleware' which is list of Starlette Middleware
            from starlette.middleware import Middleware
            kwargs["middleware"] = [Middleware(BearerAuthMiddleware, auth_token=auth_token)]
            logger.info("Bearer authentication enabled")
        else:
             logger.warning("No auth token provided. Server is running without authentication!")
    
    if args.transport == "stdio":
        mcp.run_stdio()
    elif args.transport == "sse":
        mcp.run_sse(**kwargs)
    elif args.transport == "streamable-http":
        # FastMCP seems to expose run_http_async but not a sync run_http wrapper in all versions?
        # Let's check if we can run it. The CLI uses logic to pick the right run method.
        # Based on help, there is run_http_async.
        # We can use asyncio.run(mcp.run_http_async(**kwargs))
        import asyncio
        asyncio.run(mcp.run_http_async(**kwargs))
    else:
        # Fallback to default run which might be stdio or smart detection
        mcp.run()
