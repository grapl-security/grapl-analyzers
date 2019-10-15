from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process:
        return

    p = (
        ProcessQuery().
        with_parent(
            ProcessQuery()
            .with_process_name(eq="powershell.exe")
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if not p: return

    sender.send(
        ExecutionHit(
            analyzer_name="Powershell With Child Process",
            node_view=p,
            risk_score=25,
        )
    )
