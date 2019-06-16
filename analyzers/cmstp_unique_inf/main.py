
from typing import Any, Optional

from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, ProcessView


def analyzer(client: DgraphClient, graph: SubgraphView, sender: Any):

    for node in graph.node_iter():

        p = (
            ProcessQuery().with_process_name(ends_with="CMSTP.exe")
            .with_read_files(
                FileQuery().with_file_extension(eq=".inf")
            )
            .query_first(client, contains_node_key=node.node.node_key)
        )  # type: Optional[ProcessView]

        if not p:
            continue

        for read_file in p.read_files:
            # See if at least 4 combinations exist of CMSTP with this file name.
            f = (
                FileQuery()
                .with_file_path(eq=read_file)
                .get_count(client, max=4)
            )

            # If fewer than 4 returned, this is rare enough to track
            if f < 4:
                sender.send(
                    ExecutionHit(
                        analyzer_name="CMSTP with Unique INF",
                        node_view=p,
                        risk_score=100,
                    )
                )
