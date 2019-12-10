from typing import *

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.nodes.comparators import Not
from grapl_analyzerlib.prelude import ProcessQuery, FileQuery

try:
    from grapl_ipc_analyzer_plugin.ipc_node import IpcQuery, IpcView
    __should_load = True
except ModuleNotFoundError as e:
    print(f"WARN: {e}")
    __should_load = False


def load_analyzer():
    class SshAgentIPC(Analyzer):
        def get_queries(self) -> OneOrMany[IpcQuery]:
            return (
                IpcQuery()
                .with_ipc_creator(
                    ProcessQuery()
                    .with_bin_file(
                        FileQuery()
                        .with_file_path(eq=[Not("/usr/bin/ssh-add"), Not("/bin/ssh"), Not("/usr/bin/ssh")])
                    )
                )
                .with_ipc_recipient(
                    ProcessQuery()
                    .with_process_name(eq='ssh-agent')
                    .with_process_name(eq='sshd')
                )
            )

        def on_response(self, response: IpcView, output: Any) -> None:
            output.send(
                ExecutionHit(
                    analyzer_name="SSH IPC",
                    node_view=response,
                    risk_score=75,
                )
            )

if __should_load:
    load_analyzer()