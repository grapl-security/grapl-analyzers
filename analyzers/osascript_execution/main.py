import os
from typing import *

import redis as redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.counters import SubgraphCounter
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.prelude import ProcessQuery, FileQuery, ProcessView
from pydgraph import DgraphClient

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = int(os.environ['COUNTCACHE_PORT'])

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)


class OsascriptExecutionWithRareFileRead(Analyzer):

    def __init__(self, dgraph_client: DgraphClient, counter: SubgraphCounter):
        super(OsascriptExecutionWithRareFileRead, self).__init__(dgraph_client)
        self.counter = counter

    def build(
            cls: Type['OsascriptExecutionWithRareFileRead'],
            dgraph_client: DgraphClient
    ) -> 'OsascriptExecutionWithRareFileRead':
        counter = SubgraphCounter(dgraph_client)
        return OsascriptExecutionWithRareFileRead(dgraph_client, counter)

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_bin_file(
                FileQuery().with_file_path(eq="/usr/bin/osascript")
            )
            .with_read_files(
                FileQuery().with_file_path()
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        rare_read_file = False

        for read_file in response.get_read_files():
            count = self.counter.get_count_for(
                ProcessQuery().with_process_name(eq="osascript")
                .with_read_files(
                    FileQuery().with_file_path(read_file.get_file_path())
                )
            )
            if count < 4:
                rare_read_file = True
                break

        if rare_read_file:
            output.send(
                ExecutionHit(
                    analyzer_name="Osascript Process Execution - Rare File Read",
                    node_view=response,
                    risk_score=5,
                )
            )
