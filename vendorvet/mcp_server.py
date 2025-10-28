"""VENDORVET MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from vendorvet.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-vendorvet[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-vendorvet[mcp]'")
        return 1
    app = FastMCP("vendorvet")

    @app.tool()
    def vendorvet_scan(target: str) -> str:
        """Third-party / vendor risk questionnaires with SBOM cross-ref. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
