
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    # TODO: Reenable
    return
    # unpackers = ["7zip.exe", "winrar.exe", "zip.exe"]
    #
    # process = node.as_process_view()
    # if not process:
    #     return
    #
    # p = (
    #     ProcessQuery()
    #     .with_bin_file(
    #         FileQuery().with_creator(
    #             ProcessQuery()
    #             .with_process_name(eq=unpackers)
    #         )
    #     )
    #     .query_first(client, contains_node_key=process.node_key)
    # )
    #
    # if p:
    #     sender.send(
    #         ExecutionHit(
    #             analyzer_name="Process Executing From Unpacked File",
    #             node_view=p,
    #             risk_score=15,
    #         )
    #     )

