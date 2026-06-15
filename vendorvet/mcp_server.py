"""VENDORVET MCP server — exposes assess_vendor() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from vendorvet.core import assess_vendor, to_dict


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-vendorvet[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-vendorvet[mcp]'")
        return 1
    app = FastMCP("vendorvet")

    @app.tool()
    def vendorvet_scan(questionnaire: dict) -> str:
        """Score a vendor security questionnaire. Returns JSON findings."""
        result = assess_vendor(questionnaire=questionnaire)
        return json.dumps(to_dict(result), indent=2, sort_keys=True)

    app.run()
    return 0
