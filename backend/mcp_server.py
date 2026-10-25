"""FastMCP Server for Blast Radius supply-chain security agent.

Runs over stdio to provide LLM agents with real-time graph intelligence,
attack path tracing, chokepoint identification, and remediation planning.
"""

import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from backend import tools

mcp = FastMCP("blast-radius")


@mcp.tool()
def overview() -> dict[str, Any]:
    """Retrieve high-level supply-chain security metrics and repository posture.

    WHEN TO USE:
    Call this tool first when starting security triage, greeting the user, or needing
    an executive summary of total packages, vulnerability counts, direct dependencies,
    and overall Blast Score.
    """
    return tools.overview()


@mcp.tool()
def top_threats(limit: int = 10) -> dict[str, Any]:
    """Retrieve top vulnerabilities prioritized and ranked strictly by Vuln.risk.

    WHEN TO USE:
    Call this tool when prioritizing which vulnerabilities require immediate attention,
    triaging critical/high-severity advisories, or reviewing the most severe CVEs/GHSAs
    in the application tree.
    """
    return tools.top_threats(limit=limit)


@mcp.tool()
def attack_path(target: str) -> dict[str, Any]:
    """Find the shortest import path from App to a target vulnerability or package.

    WHEN TO USE:
    Call this tool when investigating how a specific vulnerability (e.g. 'GHSA-3p68-rc4w-qgx5')
    or transitive package (e.g. 'axios@0.21.1' or 'qs') enters the dependency graph and reaches
    your application root.
    """
    return tools.attack_path(target=target)


@mcp.tool()
def blast_radius(package: str) -> dict[str, Any]:
    """Execute BFS on REQUIRED_BY to map upstream dependents and affected direct roots.

    WHEN TO USE:
    Call this tool when evaluating the collateral damage or blast radius of altering,
    removing, or discovering a compromise in a specific dependency (e.g. 'axios' or 'lodash').
    """
    return tools.blast_radius(package=package)


@mcp.tool()
def chokepoints(limit: int = 5) -> dict[str, Any]:
    """Retrieve direct dependencies ranked by exclusiveRisk and betweenness centrality.

    WHEN TO USE:
    Call this tool when identifying critical direct dependencies that act as bottlenecks
    for vulnerability flow, or carry unique, unshared risks that cannot be patched via
    other upgrade paths.
    """
    return tools.chokepoints(limit=limit)


@mcp.tool()
def risk_clusters() -> dict[str, Any]:
    """Analyze package communities and their share of repository vulnerability risk.

    WHEN TO USE:
    Call this tool when analyzing modular isolation boundaries, sub-ecosystems, or determining
    which architectural partition harbors the highest proportion of security risk.
    """
    return tools.risk_clusters()


@mcp.tool()
def fix_plan(max_actions: int = 5) -> dict[str, Any]:
    """Synthesize an optimal remediation plan via greedy set cover over Fix nodes.

    WHEN TO USE:
    Call this tool when constructing a prioritized, step-by-step upgrade roadmap that maximizes
    risk reduction per engineering effort (refresh=1, override=2, breaking=4), showing residual
    Blast Score after each action.
    """
    return tools.fix_plan(max_actions=max_actions)


@mcp.tool()
def simulate(fix_ids: list[str]) -> dict[str, Any]:
    """Non-destructively simulate the outcome of applying selected security fixes.

    WHEN TO USE:
    Call this tool when previewing how a proposed list of fixes (e.g. ['fix:axios', 'fix:qs'])
    will reduce the overall Blast Score, heal specific packages, and resolve vulnerabilities
    before committing code or lockfiles.
    """
    return tools.simulate(fix_ids=fix_ids)


@mcp.tool()
def build_patch(fix_ids: list[str]) -> dict[str, Any]:
    """Generate package.json overrides, shell remediation commands, and advisory PR markdown.

    WHEN TO USE:
    Call this tool when the user requests deployable fix scripts, npm package.json overrides,
    or a complete security remediation Pull Request description ready to commit.
    """
    return tools.build_patch(fix_ids=fix_ids)


@mcp.tool()
def cypher_ro(query: str) -> dict[str, Any]:
    """Execute arbitrary read-only Cypher queries with safety checks and 200 row limit.

    WHEN TO USE:
    Call this tool when answering bespoke investigative graph questions or inspecting
    custom Cypher patterns not directly served by the dedicated high-level tools.
    Mutation keywords (CREATE, MERGE, SET, DELETE, DROP) are strictly rejected.
    """
    return tools.cypher_ro(query=query)


if __name__ == "__main__":
    mcp.run()
