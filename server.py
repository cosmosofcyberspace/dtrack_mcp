import json
from typing import Any, Optional
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("DTrackMcpServer")

# --- Sabit ayarlar ---
DTRACK_URL = "http://localhost:8081"
DTRACK_API_KEY = ""


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f"{DTRACK_URL.rstrip('/')}/api",
        headers={"X-Api-Key": DTRACK_API_KEY, "Content-Type": "application/json"},
    )


def _format_json(data: Any) -> str:
    return json.dumps(data, indent=2)


def _error_detail(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        try:
            return str(error.response.json())
        except Exception:
            return error.response.text or str(error)
    return str(error)


@mcp.tool()
def search_components(
    query: Optional[str] = None,
    group: Optional[str] = None,
    name: Optional[str] = None,
    version: Optional[str] = None,
    purl: Optional[str] = None,
) -> str:
    """Search for components in Dependency-Track. Use query for free-text (Lucene)
    search, or group/name/version/purl for identity lookup. At least one of query or
    (group|name|version|purl) must be provided.

    Args:
        query: Free-text search query (Lucene).
        group: Group (e.g. Maven groupId).
        name: Package/component name.
        version: Exact version (no range).
        purl: Package URL for identity lookup.
    """
    try:
        with _client() as c:
            if group or name or version or purl:
                params: dict[str, Any] = {"pageNumber": 1, "pageSize": 100}
                if group:
                    params["group"] = group
                if name:
                    params["name"] = name
                if version:
                    params["version"] = version
                if purl:
                    params["purl"] = purl
                r = c.get("/v1/component/identity", params=params)
                r.raise_for_status()
                return _format_json(r.json())
            if query:
                r = c.get("/v1/search/component", params={"query": query})
                r.raise_for_status()
                return _format_json(r.json())
        return (
            "Provide at least one of: query (free-text), or "
            "group/name/version/purl for identity lookup."
        )
    except Exception as error:
        return f"Component search failed: {_error_detail(error)}"


@mcp.tool()
def list_projects(
    search_text: Optional[str] = None,
    name: Optional[str] = None,
    exclude_inactive: Optional[bool] = None,
    page_size: Optional[int] = None,
) -> str:
    """List projects from Dependency-Track. Use search_text (Lucene) for partial
    match, or name for exact filter.

    Args:
        search_text: Free-text search (Lucene), partial/substring match.
        name: Filter by project name (exact).
        exclude_inactive: Exclude inactive projects.
        page_size: Page size (default 100).
    """
    try:
        with _client() as c:
            if search_text:
                r = c.get("/v1/search/project", params={"query": search_text})
                r.raise_for_status()
                return _format_json(r.json())
            params: dict[str, Any] = {
                "pageSize": page_size if page_size is not None else 100,
                "pageNumber": 1,
            }
            if name:
                params["name"] = name
            if exclude_inactive is not None:
                params["excludeInactive"] = exclude_inactive
            r = c.get("/v1/project", params=params)
            r.raise_for_status()
            return _format_json(r.json())
    except Exception as error:
        return f"List projects failed: {_error_detail(error)}"


@mcp.tool()
def get_project(project_uuid: str) -> str:
    """Get a single project by UUID. Returns full project details including tags.

    Args:
        project_uuid: The UUID of the project to retrieve.
    """
    try:
        with _client() as c:
            r = c.get(f"/v1/project/{project_uuid}")
            r.raise_for_status()
            return _format_json(r.json())
    except Exception as error:
        return f"Get project failed: {_error_detail(error)}"


@mcp.tool()
def get_projects_affected_by_vulnerability(
    source: str,
    vuln_id: str,
    exclude_inactive: Optional[bool] = None,
) -> str:
    """List projects affected by a specific vulnerability (e.g. CVE).

    Args:
        source: Vulnerability source (e.g. NVD, GITHUB, SNYK).
        vuln_id: Vulnerability ID (e.g. CVE-2024-1234).
        exclude_inactive: Exclude inactive projects.
    """
    try:
        params = None if exclude_inactive is None else {"excludeInactive": exclude_inactive}
        with _client() as c:
            r = c.get(
                f"/v1/vulnerability/source/{quote(source)}/vuln/{quote(vuln_id)}/projects",
                params=params,
            )
            r.raise_for_status()
            return _format_json(r.json())
    except Exception as error:
        return f"Get projects affected by vulnerability failed: {_error_detail(error)}"



@mcp.tool()
def find_projects_using_component(
    name: Optional[str] = None,
    group: Optional[str] = None,
    version: Optional[str] = None,
    purl: Optional[str] = None,
) -> str:
    """Find which projects use a given component, identified by name (and optionally
    group/version) or purl. Returns the list of project names (deduplicated) that
    contain this component. Use this to answer 'which projects use X'.

    Args:
        name: Component name (e.g. bootstrap).
        group: Group (e.g. Maven groupId), optional.
        version: Exact version, optional. Omit to match all versions.
        purl: Package URL, alternative to name/group/version.
    """
    try:
        params: dict[str, Any] = {"pageNumber": 1, "pageSize": 1000}
        if group:
            params["group"] = group
        if name:
            params["name"] = name
        if version:
            params["version"] = version
        if purl:
            params["purl"] = purl
        if not (name or purl):
            return "Provide at least 'name' or 'purl'."
        with _client() as c:
            r = c.get("/v1/component/identity", params=params)
            r.raise_for_status()
            data = r.json()
        names = []
        for comp in data if isinstance(data, list) else []:
            proj = comp.get("project") if isinstance(comp, dict) else None
            if proj and proj.get("name"):
                label = proj["name"]
                if proj.get("version"):
                    label += f" ({proj['version']})"
                names.append(label)
        unique = sorted(set(names))
        if not unique:
            return f"No projects found using component '{name or purl}'."
        return _format_json({"count": len(unique), "projects": unique})
    except Exception as error:
        return f"Find projects using component failed: {_error_detail(error)}"





if __name__ == "__main__":
    mcp.run()
