
from typing import Any

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    return
    # process = node.as_process_view()
    # if not process:
    #     return
    #
    # p = (
    #     ProcessQuery()
    #     .with_process_name(eq="winword.exe")
    #     .with_process_name(eq="excel.exe")
    #     .with_children(ProcessQuery())
    #     .query_first(client, contains_node_key=process.node_key)
    # )
    #
    # if p:
    #     sender.send(
    #         ExecutionHit(
    #             analyzer_name="Common Target Application With Child Process",
    #             node_view=p,
    #             risk_score=100,
    #         )
    #     )
