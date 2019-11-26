import os
from typing import *

from grapl_analyzerlib.analyzer import Analyzer
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.nodes.process_node import ProcessView
from grapl_analyzerlib.nodes.types import OneOrMany
from grapl_analyzerlib.prelude import ProcessQuery
from grapl_ipc_analyzer_plugin.ipc_node import IpcQuery, IpcView
from grapl_os_user_analyzer_plugin.auid_assumption_node import AuidAssumptionQuery
from grapl_os_user_analyzer_plugin.user_id_assumption_node import UserIdAssumptionQuery, UserIdAssumptionView


def with_assumed_user_id(process: ProcessQuery) -> ProcessQuery:
    # The ssh_process must have an associated user id
    (
        UserIdAssumptionQuery()
        .with_assuming_process(process)
        .with_user_id()
    )
    return process


def with_assumed_auid(process: ProcessQuery):
    # The ssh_process must have an associated auid
    (
        AuidAssumptionQuery()
        .with_assuming_process(process)
        .with_auid()
    )
    return process

def get_user_id(process: ProcessView) -> Optional[int]:
    user_assumption = (
        UserIdAssumptionQuery()
        .with_assuming_process(ProcessQuery().with_node_key(process.node_key))
        .with_user_id()
        .query_first(process.dgraph_client)
    )  # type: Optional[UserIdAssumptionView]
    if user_assumption:
        return user_assumption.get_used_id()

    return None

def get_auid(process: ProcessView) -> Optional[int]:
    auid_assumption = (
        AuidAssumptionQuery()
        .with_assuming_process(ProcessQuery().with_node_key(process.node_key))
        .with_auid()
        .query_first(process.dgraph_client)
    )  # type: Optional[UserIdAssumptionView]
    if auid_assumption:
        return auid_assumption.get_auid()

    return None


def get_uid_auid_lineage(
        cur_root: Optional[ProcessView],
        user_ids: Set[int] = None,
        auids: Set[int] = None,
) -> Tuple[Set[int], Set[int]]:
    if not user_ids:
        user_ids = set()

    if not auids:
        auids = set()

    if not cur_root:
        return user_ids, auids

    cur_user_id = get_user_id(cur_root)
    cur_auid = get_auid(cur_root)

    if cur_user_id is not None:
        user_ids.add(cur_user_id)
    if cur_auid is not None:
        auids.add(cur_auid)

    return get_uid_auid_lineage(cur_root.get_parent(), user_ids, auids)


class SshAgentAccessLineageAuidOrUidMismatch(Analyzer):
    # Look for IPC access where the target is ssh-agent
    def get_queries(self) -> OneOrMany[IpcQuery]:

        ssh_process_with_user = with_assumed_user_id(
            ProcessQuery()
            .with_process_name(eq='ssh-agent')
            .with_process_name(eq='sshd')
        )
        ipc_creator_with_user = with_assumed_user_id(ProcessQuery())

        ssh_process_with_auid = with_assumed_auid(
            ProcessQuery()
            .with_process_name(eq='ssh-agent')
            .with_process_name(eq='sshd')
        )
        ipc_creator_with_auid = with_assumed_auid(ProcessQuery())

        return (
            # Query to check for mismatch of uid
            IpcQuery()
            .with_ipc_creator(ssh_process_with_user)
            .with_ipc_recipient(ipc_creator_with_user),
            # Query to check for mismatch of auid
            IpcQuery()
            .with_ipc_creator(ssh_process_with_auid)
            .with_ipc_recipient(ipc_creator_with_auid),
        )

    def on_response(self, response: IpcView, output: Any):
        print(f'Received suspicious IPC view: {response.node_key}')

        src_uids, src_auids = get_uid_auid_lineage(response.get_ipc_creator())
        tgt_uids, tgt_auids = get_uid_auid_lineage(response.get_ipc_recipient())

        user_mismatch = (src_uids.issuperset(tgt_uids) or src_uids.issubset(tgt_uids))
        auid_mismatch = (src_auids.issuperset(tgt_auids) or src_auids.issubset(tgt_auids))

        if user_mismatch or auid_mismatch:
            output.send(
                ExecutionHit(
                    analyzer_name="Ssh Agent Access: UID or AUID mismatch in lineage",
                    node_view=response,
                    risk_score=100,
                )
            )



