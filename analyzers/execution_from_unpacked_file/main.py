from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.entities import ProcessQuery, FileQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Viewable


class UnpackedFileExecuting(Analyzer):

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        unpacker_names = ["7zip.exe", "winrar.exe", "zip.exe"]

        unpacker = ProcessQuery()
        for name in unpacker_names:
            unpacker.with_process_name(eq=name)

        return (
            ProcessQuery()
            .with_bin_file(
                FileQuery()
                .with_creator(
                    unpacker
                )
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        output.send(
            ExecutionHit(
                analyzer_name="Process Executing From Unpacked File",
                node_view=response,
                risk_score=15,
            )
        )
