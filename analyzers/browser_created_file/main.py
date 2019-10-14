import os

from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Not
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process: return

    p = (
        ProcessQuery()
        .with_process_name(eq="firefox.exe")
        .with_process_name(eq="chrome.exe")
        .with_created_files(
            FileQuery()
            .with_file_path(contains=Not("AppData"))
            .with_file_extension(eq=Not(".tmp"))
            .with_spawned_from(
                ProcessQuery()
            )
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        sender.send(
            ExecutionHit(
                analyzer_name="Browser Created File Executed",
                node_view=p,
                risk_score=5,
            )
        )
