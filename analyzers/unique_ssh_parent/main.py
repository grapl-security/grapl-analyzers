import os

import redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany, A
from grapl_analyzerlib.counters import ParentChildCounter
from grapl_analyzerlib.entities import ProcessQuery
from grapl_analyzerlib.execution import ExecutionHit

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)

from typing import Any, Type

from grapl_analyzerlib.entities import ProcessView
from pydgraph import DgraphClient

class RareParentOfSsh(Analyzer):

    def __init__(self, dgraph_client: DgraphClient, counter: ParentChildCounter):
        super(RareParentOfSsh, self).__init__(dgraph_client)
        self.counter = counter

    @classmethod
    def build(cls: Type[A], dgraph_client: DgraphClient) -> A:
        counter = ParentChildCounter(dgraph_client, cache=r)
        return RareParentOfSsh(dgraph_client, counter)

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name(eq="ssh")
            .with_parent(
                ProcessQuery()
                .with_process_name()
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        count = self.counter.get_count_for(
            parent_process_name=response.get_parent().get_process_name(),
            child_process_name=response.get_process_name(),
        )

        if count <= 3:
            output.send(
                ExecutionHit(
                    analyzer_name="Rare Parent of SSH",
                    node_view=response,
                    risk_score=5,
                )
            )
