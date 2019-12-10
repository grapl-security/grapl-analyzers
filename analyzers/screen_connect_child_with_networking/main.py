# import os
# from typing import *
#
# from grapl_analyzerlib.analyzer import Analyzer
# from grapl_analyzerlib.execution import ExecutionHit
# from grapl_analyzerlib.nodes.process_node import ProcessView
# from grapl_analyzerlib.nodes.types import OneOrMany
# from grapl_analyzerlib.prelude import ProcessQuery
#
#
# class ScreenConnectChildWithNetworking(Analyzer):
#     def get_queries(self) -> ProcessQuery:
#         return (
#             ProcessQuery()
#             .with_process_name(starts_with="ScreenConnect")
#             .with_children(
#                 ProcessQuery()
#                 .with_external_connections()
#             )
#         )
#
#     def on_response(self, response: IpcView, output: Any):
#
#         output.send(
#             ExecutionHit(
#                 analyzer_name="ScreenConnect child with external connections",
#                 node_view=response,
#                 risk_score=100,
#             )
#         )
#
#
#
