from __future__ import annotations

import asyncio

from apify import Actor

from src.checks.dynamic_checks import run_dynamic_checks
from src.checks.scoring import compute_score
from src.checks.static_checks import run_static_checks, sanitize_text, sanitize_url
from src.mcp_client import MCPClient
from src.report import build_markdown_report, build_report_dict


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}

        server_url: str | None = actor_input.get("serverUrl")
        auth_header: str | None = actor_input.get("authHeader") or None
        run_dynamic: bool = actor_input.get("runDynamicChecks", False)
        authorized_to_test: bool = actor_input.get("authorizedToTest", False)
        dynamic_allowlist = actor_input.get("dynamicToolAllowlist") or []
        probe_url: str | None = actor_input.get("probeUrl") or None
        max_tools: int = actor_input.get("maxToolsToTest", 10)

        if not server_url:
            await Actor.fail(status_message="Missing required input: serverUrl")
            return
        if not isinstance(dynamic_allowlist, list) or not all(
            isinstance(name, str) and name for name in dynamic_allowlist
        ):
            await Actor.fail(
                status_message="dynamicToolAllowlist must contain exact non-empty tool names"
            )
            return
        if run_dynamic and not authorized_to_test:
            await Actor.fail(
                status_message=(
                    "Dynamic checks require authorizedToTest=true; no tools were executed"
                )
            )
            return
        if run_dynamic and not dynamic_allowlist:
            await Actor.fail(
                status_message=(
                    "Dynamic checks require a non-empty dynamicToolAllowlist; "
                    "no tools were executed"
                )
            )
            return

        Actor.log.info(f"Probing MCP server at {sanitize_url(server_url)} ...")
        client = MCPClient(base_url=server_url, auth_header=auth_header)
        probe = await client.probe()

        if not probe.reachable or probe.error:
            safe_error = sanitize_text(probe.error or "Unknown connection error")
            Actor.log.error(f"MCP discovery could not be completed: {safe_error}")
            static_report = run_static_checks([])
            score = compute_score(static_report, None)
            report_dict = build_report_dict(
                server_url,
                probe,
                static_report,
                None,
                score,
                dynamic_tool_allowlist=dynamic_allowlist,
                auth_header_supplied=bool(auth_header),
            )
            report_dict["score"] = None
            report_dict["grade"] = None
            report_dict["error"] = safe_error
            report_dict["limitations"].append(
                "MCP initialization or tool discovery did not complete, so no score was assigned."
            )
            await Actor.push_data(report_dict)
            store = await Actor.open_key_value_store()
            await store.set_value("OUTPUT", report_dict)
            await store.set_value(
                "REPORT.md",
                build_markdown_report(report_dict),
                content_type="text/markdown",
            )
            await Actor.fail(status_message=f"MCP discovery failed: {safe_error}")
            return

        Actor.log.info(f"Found {len(probe.tools)} tools. Running static checks ...")
        static_report = run_static_checks(probe.tools)

        dynamic_report = None
        if run_dynamic and probe.tools:
            Actor.log.warning(
                "Dynamic checks are enabled. Tool calls may trigger side effects on the target."
            )
            Actor.log.info(
                f"Testing up to {max_tools} exact allowlisted tools dynamically ..."
            )
            dynamic_report = await run_dynamic_checks(
                client_wrapper=client,
                tools=probe.tools,
                authorized_to_test=authorized_to_test,
                dynamic_tool_allowlist=dynamic_allowlist,
                probe_url=probe_url,
                max_tools=max_tools,
                also_test_unauth=bool(auth_header),
            )
        elif run_dynamic:
            Actor.log.warning("No tools were advertised; no dynamic tool calls were made.")
            dynamic_report = await run_dynamic_checks(
                client_wrapper=client,
                tools=[],
                authorized_to_test=authorized_to_test,
                dynamic_tool_allowlist=dynamic_allowlist,
                probe_url=probe_url,
                max_tools=max_tools,
                also_test_unauth=bool(auth_header),
            )

        score = compute_score(static_report, dynamic_report)
        report_dict = build_report_dict(
            server_url,
            probe,
            static_report,
            dynamic_report,
            score,
            dynamic_tool_allowlist=dynamic_allowlist,
            auth_header_supplied=bool(auth_header),
        )
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
