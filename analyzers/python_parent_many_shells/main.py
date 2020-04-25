from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.prelude import ProcessQuery, FileQuery, ProcessView


class PythonParentWithManyShells(Analyzer):

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name(eq="python")
            .with_children(
                ProcessQuery()
                .with_bin_file(
                    FileQuery()
                    .with_file_path(eq="/bin/sh")
                    .with_file_path(eq="/bin/bash")
                )
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        asset_id = response.get_asset().get_hostname()

        output.send(
            ExecutionHit(
                analyzer_name="Python Process With Many Shells",
                node_view=response,
                risk_score=5,
                lenses=asset_id,
            )
        )
