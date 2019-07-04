import os

from typing import Any

import redis

from grapl_analyzerlib.counters import ParentChildCounter, Seen
from grapl_analyzerlib.entity_queries import Not
from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, NodeView


COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0)


def analyzer(client: DgraphClient, node: NodeView, sender: Any):

    parent_whitelist = [
        "svchost.exe",
        "RuntimeBroker.exe",
        "chrome.exe",
        "explorer.exe",
        "SIHClient.exe",
        "conhost.exe",
        "MpCmdRun.exe",
        "GoogleUpdateComRegisterShell64.exe",
        "GoogleUpdate.exe",
        "notepad.exe",
        "OneDrive.exe",
        "VBoxTray.exe",
        "Firefox Installer.exe",
    ]

    counter = ParentChildCounter(client, cache=r)

    process = node.as_process_view()
    if not process:
        return

    p = (
        ProcessQuery()
        .with_process_name(eq=[Not(p) for p in parent_whitelist])
        .with_children(
            ProcessQuery()
            .with_process_name(eq="cmd.exe")
        )
        .query_first(client, contains_node_key=process.node_key)
    )

    if p:
        count = counter.get_count_for(
            parent_process_name=p.process_name,
            child_process_name="cmd.exe",
            excluding=process.node_key
        )

        if count <= Seen.Once:
            sender.send(
                ExecutionHit(
                    analyzer_name="Rare Parent of cmd.exe",
                    node_view=p,
                    risk_score=5,
                )
            )
