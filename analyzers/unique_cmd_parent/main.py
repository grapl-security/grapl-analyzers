
from typing import Any

from grapl_analyzerlib.counters import ParentChildCounter, Seen
from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery


def analyzer(client: DgraphClient, graph: SubgraphView, sender: Any):

    counter = ParentChildCounter(client)

    for process in graph.process_iter():
        p = (
            ProcessQuery()
            .with_process_name()
            .with_children(
                ProcessQuery()
                .with_process_name(eq="cmd.exe")
            )
            .query_first(client, contains_node_key=process.node_key)
        )

        if p:
            count = counter.get_count_for(
                parent_process_name=p.process_name,
                child_process_name="cmd.exe",
                excluding=process.node_key
            )

            if count <= Seen.Once:
                sender.send(
                    ExecutionHit(
                        analyzer_name="Rare Parent of cmd.exe",
                        node_view=p,
                        risk_score=5,
                    )
                )
