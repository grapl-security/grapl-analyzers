import os

import redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany, A
from grapl_analyzerlib.counters import GrandParentGrandChildCounter
from grapl_analyzerlib.prelude import ProcessQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=int(COUNTCACHE_PORT), db=0, decode_responses=True)

from typing import Any, Type

from pydgraph import DgraphClient


class RareGrandParentOfSsh(Analyzer):

    def __init__(self, dgraph_client: DgraphClient, counter: GrandParentGrandChildCounter):
        super(RareGrandParentOfSsh, self).__init__(dgraph_client)
        self.counter = counter

    @classmethod
    def build(cls: Type[A], dgraph_client: DgraphClient) -> A:
        counter = GrandParentGrandChildCounter(dgraph_client, cache=r)
        return RareGrandParentOfSsh(dgraph_client, counter)

    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name(eq="ssh")
            .with_parent(
                ProcessQuery().with_parent(
                    ProcessQuery()
                    .with_process_name()
                )
            )
        )

    def on_response(self, response: ProcessView, output: Any):
        count = self.counter.get_count_for(
            grand_parent_process_name=response.get_parent().get_parent().get_process_name(),
            grand_child_process_name=response.get_process_name(),
        )

        print(f'Counted {count} for parent -> ssh')

        if count <= 3:
            output.send(
                ExecutionHit(
                    analyzer_name="Rare GrandParent of SSH",
                    node_view=response,
                    risk_score=5,
                )
            )
