from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.entities import ProcessQuery, FileQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit


class SshSocketRead(Analyzer):

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_read_files(
                FileQuery().with_file_path(contains="/tmp/ssh")
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        output.send(
            ExecutionHit(
                analyzer_name="SSH Socket Read",
                node_view=response,
                risk_score=5,
            )
        )