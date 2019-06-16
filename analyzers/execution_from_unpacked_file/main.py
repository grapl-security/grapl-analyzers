
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery


def analyzer(client: DgraphClient, graph: SubgraphView, sender: Any):

    unpackers = ["7zip.exe", "winrar.exe", "zip.exe"]

    for process in graph.process_iter():
        p = (
            ProcessQuery()
            .with_bin_file(
                FileQuery().with_creator(
                    ProcessQuery()
                    .with_process_name(eq=unpackers)
                )
            )
            .query_first(client, contains_node_key=process.node_key)
        )

        if p:
            sender.send(
                ExecutionHit(
                    analyzer_name="Process Executing From Unpacked File",
                    node_view=p,
                    risk_score=15,
                )
            )

