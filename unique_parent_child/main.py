
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.counters import ParentChildCounter
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView


def analyzer(client: DgraphClient, graph: SubgraphView, sender: Any):

    counter = ParentChildCounter(client)

    for process in graph.process_iter():
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
            continue

        for child in p.children:
            count = counter.get_count_for(
                parent_process_name=p.get_process_name(),
                child_process_name=child.get_process_name(),
                excluding=process.node_key
            )

            if count <= 3:
                sender.send(
                    ExecutionHit(
                        analyzer_name="Rare Parent Child Process",
                        node_view=p,
                        risk_score=70,
                    )
                )
