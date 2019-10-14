import os

from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process:
        return

    # Look for all processes that have deleted files where the file had been executed
    p = (
        ProcessQuery()
        .with_deleted_files(
            FileQuery()
            .with_spawned_from(
                ProcessQuery()
            )
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        sender.send(
            ExecutionHit(
                analyzer_name="Process Deletes Binary File",
                node_view=p,
                risk_score=20,
            )
        )
