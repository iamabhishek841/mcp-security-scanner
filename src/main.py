from __future__ import annotations

import asyncio

from apify import Actor

from src.mcp_client import MCPClient
from src.checks.static_checks import run_static_checks
from src.checks.dynamic_checks import run_dynamic_checks
from src.checks.scoring import compute_score
from src.report import build_report_dict, build_markdown_report


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}

        server_url: str | None = actor_input.get("serverUrl")
        auth_header: str | None = actor_input.get("authHeader") or None
        run_dynamic: bool = actor_input.get("runDynamicChecks", True)
        max_tools: int = actor_input.get("maxToolsToTest", 10)

        if not server_url:
            await Actor.fail(status_message="Missing required input: serverUrl")
            return

        Actor.log.info(f"Probing MCP server at {server_url} ...")
        client = MCPClient(base_url=server_url, auth_header=auth_header)
        probe = await client.probe()

        if not probe.reachable:
            Actor.log.error(f"Server unreachable: {probe.error}")
            await Actor.push_data(
                {
                    "server_url": server_url,
                    "reachable": False,
                    "error": probe.error,
                }
            )
            await Actor.fail(status_message=f"Could not reach MCP server: {probe.error}")
            return

        if probe.error:
            Actor.log.warning(f"Reached server but tools/list failed: {probe.error}")

        Actor.log.info(f"Found {len(probe.tools)} tools. Running static checks ...")
        static_report = run_static_checks(probe.tools)

        dynamic_report = None
        if run_dynamic and probe.tools:
            Actor.log.info(f"Running dynamic checks on up to {max_tools} tools ...")
            dynamic_report = await run_dynamic_checks(
                client_wrapper=client,
                tools=probe.tools,
                max_tools=max_tools,
                also_test_unauth=bool(auth_header),
            )

        score = compute_score(static_report, dynamic_report)
        report_dict = build_report_dict(server_url, probe, static_report, dynamic_report, score)
        report_md = build_markdown_report(report_dict)

        # Push structured result to the default dataset (what "Export results" gives you)
        await Actor.push_data(report_dict)

        # Save the markdown report to the key-value store so it can be downloaded/shared
        store = await Actor.open_key_value_store()
        await store.set_value("REPORT.md", report_md, content_type="text/markdown")
        await store.set_value("OUTPUT", report_dict)

        Actor.log.info(f"Scan complete. Score: {score.score}/100 (Grade {score.grade})")


if __name__ == "__main__":
    asyncio.run(main())
