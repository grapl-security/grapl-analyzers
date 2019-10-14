
from typing import Any

from pydgraph import DgraphClient

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.entities import ProcessQuery, ExternalIpQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    # Catch cases where a child process P with a parent of `cmd.exe`
    # makes outbound external network requests

    process = node.as_process_view()
    if not process:
        return

    p = (
        ProcessQuery()
        .with_parent(ProcessQuery().with_process_name(eq="cmd.exe"))
        .with_created_connection(ExternalIpQuery())
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        sender.send(
            ExecutionHit(
                analyzer_name="Cmd Child External Network",
                node_view=p,
                risk_score=5,
            )
        )

