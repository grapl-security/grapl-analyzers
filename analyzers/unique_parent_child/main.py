
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.counters import ParentChildCounter, Seen
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    counter = ParentChildCounter(client)

    process = node.as_process_view()
    if not process:
        return

    p = (
        ProcessQuery()
        .with_process_name()
        .with_children(
            ProcessQuery()
            .with_process_name()
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if not p:
        return

    for child in p.children:
        count = counter.get_count_for(
            parent_process_name=p.get_process_name(),
            child_process_name=child.get_process_name(),
            excluding=process.node_key
        )

        if count < Seen.Many:
            sender.send(
                ExecutionHit(
                    analyzer_name="Rare Parent Child Process",
                    node_view=p,
                    risk_score=70,
                )
            )
