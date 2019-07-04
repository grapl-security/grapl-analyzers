import os

from typing import Any, Optional

import redis

from grapl_analyzerlib.execution import ExecutionHit, ExecutionComplete
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, ProcessView, NodeView


COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)


def count_path(dg_client, path, max=4):
    cached_count = r.get(path)
    if cached_count:
        cached_count = int(cached_count)

    if cached_count and cached_count >= max:
        print(f'Cached count: {cached_count}')
        return cached_count

    count = (
        ProcessQuery().with_process_name(ends_with="CMSTP.exe")
        .with_read_files(
            FileQuery().with_file_path(eq=path)
        )
        .get_count(dg_client, max=4)
    )

    if count >= max:
        if not cached_count:
            r.set(path, count)
        elif count >= cached_count:
            r.set(path, count)

    return count


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    node = node.as_process_view()
    if not node:
        return

    p = (
        ProcessQuery().with_process_name(eq="CMSTP.exe")
        .with_read_files(
            FileQuery().with_file_extension(eq=".inf")
        )
        .query_first(client, contains_node_key=node.node_key)
    )  # type: Optional[ProcessView]

    if not p:
        return

    for read_file in p.read_files:
        # See if at least 4 combinations exist of CMSTP with this file name.
        count = count_path(client, read_file.get_file_path())

        # If fewer than 4 returned, this is rare enough to track
        if count < 4:
            sender.send(
                ExecutionHit(
                    analyzer_name="CMSTP with Unique INF",
                    node_view=p,
                    risk_score=100,
                )
            )
