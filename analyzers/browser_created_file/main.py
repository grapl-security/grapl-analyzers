
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    browsers = [
        "chrome.exe",
        "firefox.exe",
        "microsoftedgecp.exe",
        "microsoftedge.exe",
        "iexplorer.exe"
    ]

    process = node.as_process_view()
    if not process:
        return

    p = (
        ProcessQuery()
        .with_process_name(eq=browsers)
        .with_created_files(
            FileQuery()
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        sender.send(
            ExecutionHit(
                analyzer_name="Browser Created File",
                node_view=p,
                risk_score=10,
            )
        )
