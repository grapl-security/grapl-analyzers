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

    risk_score = 5

    count = (
        ProcessQuery()
        .with_process_name(eq=p.get_process_name())
        .with_parent(
            ProcessQuery()
            .with_process_name(eq="powershell.exe")
        )
        .get_count(client, max=3)
    )

    if count < 3:
        risk_score += 15

    sender.send(
        ExecutionHit(
            analyzer_name="Powershell With Child Process",
            node_view=p.get_parent(),
            risk_score=risk_score,
        )
    )
