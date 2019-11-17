import os

import redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.execution import ExecutionHit
from typing import *

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)

from typing import Any
from grapl_analyzerlib.prelude import ProcessQuery, ProcessView
from grapl_ipc_analyzer_plugin.ipc_node import IpcQuery, IpcView
from grapl_os_user_analyzer_plugin.assumed_user_id_node import AssumedUserIdQuery
from grapl_os_user_analyzer_plugin.assumed_auid_node import AssumedAuidQuery


def with_assumed_user_id(process: ProcessQuery) -> ProcessQuery:
    # The ssh_process must have an associated user id
    (
        AssumedUserIdQuery()
        .with_assuming_process(process)
        .with_user_id()
    )
    return process


def with_assumed_auid(process: ProcessQuery):
    # The ssh_process must have an associated auid
    (
        AssumedAuidQuery()
            .with_assuming_process(process)
            .with_auid()
    )
    return process


def get_user_id(process: ProcessView) -> Optional[int]:
    user_assumption = (
        AssumedUserIdQuery()
            .with_assuming_process(ProcessQuery().with_node_key(process.node_key))
            .with_user_id()
            .query_first(process.dgraph_client)
    )  # type: Optional[AssumedUserIdView]
    if user_assumption:
        return user_assumption.get_used_id()

    return None

def get_auid(process: ProcessView) -> Optional[int]:
    auid_assumption = (
        AssumedAuidQuery()
            .with_assuming_process(ProcessQuery().with_node_key(process.node_key))
            .with_auid()
            .query_first(process.dgraph_client)
    )  # type: Optional[AssumedUserIdView]
    if auid_assumption:
        return auid_assumption.get_auid()

    return None


class SshAgentAccessAuidOrUidMismatch(Analyzer):
    # Look for IPC access where the target is ssh-agent
    def get_queries(self) -> OneOrMany[IpcQuery]:
        return (
            # Query to check for mismatch of uid
            IpcQuery()
            .with_ipc_creator(
                with_assumed_user_id(ProcessQuery())
            )
            .with_ipc_recipient(
                ProcessQuery()
                .with_user_id()
                .with_process_name(eq='ssh-agent')
                .with_process_name(eq='sshd')
            ),
            # Query to check for mismatch of auid
            IpcQuery()
            .with_ipc_creator(
                ProcessQuery().with_auid()
            )
            .with_ipc_recipient(
                ProcessQuery()
                .with_auid()
                .with_process_name(eq='ssh-agent')
                .with_process_name(eq='sshd')
            )
        )

    def on_response(self, response: IpcView, output: Any):
        print(f'Received suspicious IPC view: {response.node_key}')

        ipc_creator = response.get_ipc_creator()
        ssh_agent = response.get_ipc_recipient()

        user_mismatch = get_user_id(ipc_creator) != get_user_id(ssh_agent)
        auid_mismatch = get_auid(ipc_creator) != get_auid(ssh_agent)

        if user_mismatch or auid_mismatch:
            output.send(
                ExecutionHit(
                    analyzer_name="Ssh Agent Access: UID or AUID mismatch",
                    node_view=response,
                    risk_score=100,
                )
            )
