from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process: return

    p = (
        ProcessQuery()
        .with_process_name()
        .with_parent(
            ProcessQuery()
            .with_process_name()
            .with_bin_file(
                FileQuery()
            )
        )
        .with_bin_file(
            FileQuery()
            .with_file_path(contains='Windows\\\\System32\\')
            .with_file_path(contains='Windows\\\\SysWow64\\')
        )
        .query(client, contains_node_key=process.node_key)
    )

    if not p: return

    count = (
        ProcessQuery()
        .with_process_name(eq=p.get_process_name())
        .with_parent(
            ProcessQuery()
                .with_process_name(eq=p.get_parent().get_process_name())
        )
        .get_count(client, max=2)
    )
    if count <= 2:
        sender.send(
            ExecutionHit(
                analyzer_name="Unique Windows Builtin Execution",
                node_view=p,
                risk_score=15,
            )
        )
