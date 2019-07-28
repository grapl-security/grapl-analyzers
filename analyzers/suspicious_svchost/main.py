
from typing import Any

from grapl_analyzerlib.entities import ProcessQuery, NodeView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Not
from pydgraph import DgraphClient


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    valid_parents = [
        Not("services.exe"),
        Not("smss.exe"),
        Not("ngentask.exe"),
        Not("userinit.exe"),
        Not("GoogleUpdate.exe"),
        Not("conhost.exe"),
    ]

    process = node.as_process_view()
    if not process:
        return
    
    assert process.node_key, 'missing node_key'
    p = (
        ProcessQuery()
        .with_process_name(eq=valid_parents)
        .with_children(
            ProcessQuery().with_process_name(eq="svchost.exe")
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        print('Got a hit for Suspicious svchost')
        sender.send(
            ExecutionHit(
                analyzer_name="Suspicious svchost",
                node_view=p,
                risk_score=10,
            )
        )
