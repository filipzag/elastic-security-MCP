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


def _list_rules(limit: int = 20, page: int = 1):
    endpoint = "/api/alerting/rules/_find"
    params = {
        "per_page": limit,
        "page": page
    }
    return _make_request("GET", endpoint, params=params)

@mcp.tool()
def list_rules(limit: int = 20, page: int = 1):
    """
    List detection rules from Elastic Security.
    
    Args:
        limit: The number of rules to return per page. Default 20.
        page: The page number to return. Default 1.
    """
    return _list_rules(limit, page)

def _upload_rule(rule_content: str):
    try:
        data = json.loads(rule_content)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON content: {str(e)}"}
        
    rule_id = data.get("id")
    if rule_id:
        endpoint = f"/api/alerting/rule/{rule_id}"
    else:
        endpoint = "/api/alerting/rule"
        
    return _make_request("POST", endpoint, json_data=data)

@mcp.tool()
def upload_rule(rule_content: str):
    """
    Upload (create) a new detection rule.
    
    Args:
        rule_content: The JSON string content of the rule to create.
    """
    return _upload_rule(rule_content)

def _enable_rule(rule_id: str):
    endpoint = f"/api/alerting/rule/{rule_id}/_enable"
    return _make_request("POST", endpoint)

@mcp.tool()
def enable_rule(rule_id: str):
    """
    Enable a detection rule by its ID.
    
    Args:
        rule_id: The unique identifier of the rule.
    """
    return _enable_rule(rule_id)

def _disable_rule(rule_id: str):
    endpoint = f"/api/alerting/rule/{rule_id}/_disable"
    return _make_request("POST", endpoint)

@mcp.tool()
def disable_rule(rule_id: str):
    """
    Disable a detection rule by its ID.
    
    Args:
        rule_id: The unique identifier of the rule.
    """
    return _disable_rule(rule_id)

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
