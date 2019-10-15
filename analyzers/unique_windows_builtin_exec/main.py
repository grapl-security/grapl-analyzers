from typing import Any

import redis

from grapl_analyzerlib.counters import ParentChildCounter, Seen
from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)

def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    process = node.as_process_view()
    if not process: return

    counter = ParentChildCounter(client, cache=r)

    p = (
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
        .query_first(client, contains_node_key=process.node_key)
    )

    if not p: return

    count = counter.get_count_for(
        parent_process_name=p.get_parent().get_process_name(),
        child_process_name=p.get_process_name(),
    )

    if count <= 4:
        sender.send(
            ExecutionHit(
                analyzer_name="Unique Windows Builtin Execution",
                node_view=p,
                risk_score=15,
            )
        )
