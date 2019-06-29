
from typing import Any, Optional

from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.counters import ParentChildCounter, Seen
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, NodeView, ProcessView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    # TODO: Reenable this analyzer
    return
    # counter = ParentChildCounter(client)
    #
    # process = node.as_process_view()
    # if not process:
    #     return
    #
    # p = (
    #     ProcessQuery()
    #     .with_process_name()
    #     .with_parent(
    #         ProcessQuery()
    #         .with_process_name()
    #     )
    #     .query_first(client, contains_node_key=process.node_key)
    # )  # type: Optional[ProcessView]
    #
    # if not p:
    #     return
    #
    # parent = p.get_parent()
    #
    # count = counter.get_count_for(
    #     parent_process_name=p.get_process_name(),
    #     child_process_name=parent.get_process_name(),
    #     excluding=process.node_key
    # )
    #
    # if count < Seen.Many:
    #     sender.send(
    #         ExecutionHit(
    #             analyzer_name="Rare Parent Child Process",
    #             node_view=p,
    #             risk_score=70,
    #         )
    #     )
