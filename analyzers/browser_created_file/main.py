from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.prelude import ProcessQuery, FileQuery, Not, ProcessView
from grapl_analyzerlib.execution import ExecutionHit


class BrowserCreatedFile(Analyzer):

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name(eq="firefox.exe")
            .with_process_name(eq="chrome.exe")
            .with_created_files(
                FileQuery()
                .with_file_path(contains=[Not("AppData"), Not("tmp")])
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        asset_id = response.get_asset().get_hostname()

        output.send(
            ExecutionHit(
                analyzer_name="Browser Created File",
                node_view=response,
                risk_score=5,
                lenses=asset_id,
            )
        )
