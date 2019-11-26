import os
from typing import Any, Type

import redis
from grapl_analyzerlib.analyzer import Analyzer, A, OneOrMany
from grapl_analyzerlib.counters import ParentChildCounter
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.prelude import ProcessQuery, FileQuery, ProcessView
from pydgraph import DgraphClient

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=int(COUNTCACHE_PORT), db=0, decode_responses=True)


class UniqueWindowsBuiltinExecution(Analyzer):
    def __init__(self, dgraph_client: DgraphClient, counter: ParentChildCounter):
        super(UniqueWindowsBuiltinExecution, self).__init__(dgraph_client)
        self.counter = counter

    @classmethod
    def build(cls: Type[A], dgraph_client: DgraphClient) -> A:
        counter = ParentChildCounter(dgraph_client)
        return UniqueWindowsBuiltinExecution(dgraph_client, counter)

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name()
            .with_parent(
                ProcessQuery()
                .with_process_name()
                .with_bin_file(
                    FileQuery()
                )
            )
            .with_bin_file(
                FileQuery()
                .with_file_path(contains='Windows\\\\System32\\')
                .with_file_path(contains='Windows\\\\SysWow64\\')
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        count = self.counter.get_count_for(
            parent_process_name=output.get_parent().get_process_name(),
            child_process_name=output.get_process_name(),
        )

        if count <= 2:
            output.send(
                ExecutionHit(
                    analyzer_name="Unique Windows Builtin Execution",
                    node_view=response,
                    risk_score=15,
                )
            )
