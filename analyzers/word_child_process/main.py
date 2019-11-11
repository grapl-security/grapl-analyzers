from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.entities import ProcessQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Viewable, Queryable


class CommonTargetWithChildProcess(Analyzer):

    def get_queries(self) -> OneOrMany[Queryable]:
        return (
            ProcessQuery()
            .with_process_name(eq="winword.exe")
            .with_process_name(eq="excel.exe")
            .with_process_name(eq="reader.exe")
            .with_children(ProcessQuery())
         )

    def on_response(self, response: ProcessView, output: Any):
        output.send(
            ExecutionHit(
                analyzer_name="Common Target Application With Child Process",
                node_view=response,
                risk_score=75,
            )
        )
