import os

from typing import Any, Optional

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView, ProcessView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process:
        return

    # SSH Hijacking
    p = (
        ProcessQuery()
        .with_read_files(
            FileQuery()
            .with_file_path(contains="/tmp/ssh")
            .with_creator(ProcessQuery())
        )
        .query_first(client, contains_node_key=process.node_key)
    )  # type: Optional[ProcessView]

    if p:
        # If reader is not the same as the creator
        if any([p.node_key != rf.node_key for rf in p.get_read_files()]):
            return

        sender.send(
            ExecutionHit(
                analyzer_name="Process Deletes Binary File",
                node_view=p,
                risk_score=20,
            )
        )
