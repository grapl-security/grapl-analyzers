
from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.nodes.ip_port_node import IpPortQuery
from grapl_analyzerlib.prelude import ProcessQuery, ProcessView
from grapl_analyzerlib.nodes.process_outbound_network_connection import ProcessOutboundConnectionQuery
from grapl_analyzerlib.execution import ExecutionHit


class CmdChildNetwork(Analyzer):

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name()
            .with_parent(ProcessQuery().with_process_name(eq="cmd.exe"))
            .with_created_connections()
        )

    def on_response(self, response: ProcessView, output: Any):
        asset_id = response.get_asset().get_hostname()

        output.send(
            ExecutionHit(
                analyzer_name="Cmd Child Network",
                node_view=response,
                risk_score=5,
                lenses=asset_id
            )
        )


