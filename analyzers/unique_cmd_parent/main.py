import os
from typing import Any

import redis
from grapl_analyzerlib.counters import ParentChildCounter, Seen
from grapl_analyzerlib.entities import ProcessQuery, NodeView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Not
from pydgraph import DgraphClient

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    return
    # parent_whitelist = [
    #     Not("svchost.exe"),
    #     Not("RuntimeBroker.exe"),
    #     Not("chrome.exe"),
    #     Not("explorer.exe"),
    #     Not("SIHClient.exe"),
    #     Not("conhost.exe"),
    #     Not("MpCmdRun.exe"),
    #     Not("GoogleUpdateComRegisterShell64.exe"),
    #     Not("GoogleUpdate.exe"),
    #     Not("notepad.exe"),
    #     Not("OneDrive.exe"),
    #     Not("VBoxTray.exe"),
    #     Not("Firefox Installer.exe"),
    # ]
    #
    # counter = ParentChildCounter(client, cache=r)
    #
    # process = node.as_process_view()
    # if not process:
    #     return
    #
    # p = (
    #     ProcessQuery()
    #     .with_process_name(eq=parent_whitelist)
    #     .with_children(
    #         ProcessQuery()
    #         .with_process_name(eq="cmd.exe")
    #     )
    #     .query_first(client, contains_node_key=process.node_key)
    # )
    #
    # if p:
    #     count = counter.get_count_for(
    #         parent_process_name=p.process_name,
    #         child_process_name="cmd.exe",
    #         excluding=process.node_key
    #     )
    #
    #     if count <= Seen.Once:
    #         sender.send(
    #             ExecutionHit(
    #                 analyzer_name="Rare Parent of cmd.exe",
    #                 node_view=p,
    #                 risk_score=5,
    #             )
    #         )
