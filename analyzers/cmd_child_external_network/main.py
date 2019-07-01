
from typing import Any

from pydgraph import DgraphClient

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, ExternalIpQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    process = node.as_process_view()
    if not process:
        return

    cmd = ProcessQuery().with_process_name(eq="cmd.exe")

    cmd_child = ProcessQuery().with_parent(cmd)

    cmd_child.with_created_connection(ExternalIpQuery())

    p = cmd_child.query_first(client, contains_node_key=process.node_key)

    if p:
        sender.send(
            ExecutionHit(
                analyzer_name="Cmd Child External Network",
                node_view=p,
                risk_score=5,
            )
        )
