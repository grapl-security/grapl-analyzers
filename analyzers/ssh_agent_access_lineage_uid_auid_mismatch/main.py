from copy import deepcopy
from typing import Union, Optional, Any, List, Tuple, Callable, Type

from grapl_analyzerlib.entities import DynamicNodeQuery, ProcessView, PV
from grapl_analyzerlib.querying import Viewable, V, StrCmp, IntCmp
from pydgraph import DgraphClient

import os
from typing import Set

import redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.entities import ProcessQuery
from grapl_analyzerlib.execution import ExecutionHit

COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
COUNTCACHE_PORT = os.environ['COUNTCACHE_PORT']

r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)

from copy import deepcopy
from typing import Union, Optional, Any, List, Tuple, Callable, Type

from grapl_analyzerlib.entities import DynamicNodeQuery, ProcessView, PV
from grapl_analyzerlib.querying import Viewable, V, StrCmp, IntCmp
from pydgraph import DgraphClient


class InterProcessCommunicationQuery(DynamicNodeQuery):
    def __init__(self) -> None:
        super(InterProcessCommunicationQuery, self).__init__("InterProcessCommunication", InterProcessCommunicationView)

    def with_key(self, eq=StrCmp, contains=StrCmp, ends_with=StrCmp) -> 'InterProcessCommunicationQuery':
        self.with_property_str_filter("key", eq=eq, contains=contains, ends_with=ends_with)
        return self

    def with_src_pid(self, eq=IntCmp, gt=IntCmp, lt=IntCmp) -> 'InterProcessCommunicationQuery':
        self.with_property_int_filter("src_pid", eq=eq, gt=gt, lt=lt)
        return self

    def with_dst_pid(self, eq=IntCmp, gt=IntCmp, lt=IntCmp) -> 'InterProcessCommunicationQuery':
        self.with_property_int_filter("dst_pid", eq=eq, gt=gt, lt=lt)
        return self

    def with_ipc_type(self, eq=StrCmp, contains=StrCmp, ends_with=StrCmp) -> 'InterProcessCommunicationQuery':
        self.with_property_str_filter("ipc_type", eq=eq, contains=contains, ends_with=ends_with)
        return self

    def with_ipc_creator(self, created_ipc: 'PQ') -> 'InterProcessCommunicationQuery':
        created_ipc = deepcopy(created_ipc)
        self.with_edge_filter("created_ipc", created_ipc)
        created_ipc.with_reverse_edge_filter("~created_ipc", self)
        return self

    def with_ipc_recipient(self, received_ipc: 'PQ') -> 'InterProcessCommunicationQuery':
        received_ipc = deepcopy(received_ipc)
        self.with_edge_filter("received_ipc", received_ipc)
        received_ipc.with_reverse_edge_filter("~received_ipc", self)
        return self


class InterProcessCommunicationView(Viewable):

    def __init__(
            self,
            dgraph_client: DgraphClient,
            node_key: str,
            uid: str,
            key: str = None,
            src_pid: int = None,
            dst_pid: int = None,
            ipc_type: str = None,
            created_ipc: Optional["PV"] = None,
            received_ipc: Optional["PV"] = None,
            **kwargs,
    ):
        super(InterProcessCommunicationView, self).__init__(dgraph_client, node_key, uid)
        self.key = key
        self.src_pid = src_pid
        self.dst_pid = dst_pid
        self.ipc_type = ipc_type

        self.created_ipc = created_ipc
        self.received_ipc = received_ipc

    @staticmethod
    def get_property_types() -> List[Tuple[str, Callable[[Any], Union[str, int]]]]:
        return [
            ("key", str),
            ("ipc_type", str),
            ("src_pid", int),
            ("dst_pid", int),
        ]

    @staticmethod
    def get_edge_types() -> List[Tuple[str, Union[List[Type[V]], Type[V]]]]:
        return [
            ("created_ipc", ProcessView),
            ("received_ipc", ProcessView),
        ]

    def get_property_tuples(self) -> List[Tuple[str, Any]]:
        prop_tuples = [
            ("node_key", self.node_key),
            ("key", self.key),
            ("src_pid", self.src_pid),
            ("dst_pid", self.dst_pid),
            ("ipc_type", self.ipc_type),
        ]

        return [pt for pt in prop_tuples if pt[1]]


    def get_edge_tuples(self) -> List[Tuple[str, Union[List[Type[V]], Type[V]]]]:
        edge_tuples = [
            ("created_ipc", self.created_ipc),
            ("received_ipc", self.received_ipc),
        ]

        return [et for et in edge_tuples if et[1]]

    @staticmethod
    def get_edges() -> List[Tuple[str, Union[List[Type[V]], Type[V]]]]:
        return [
            ("created_ipc", ProcessView),
            ("received_ipc", ProcessView),
        ]

    def get_neighbors(self):
        return [
            n for n in (self.created_ipc, self.received_ipc) if n
        ]

    def get_key(self) -> Optional[str]:
        self.key = self.get_property('key', str)
        return self.key

    def get_src_pid(self) -> Optional[int]:
        self.src_pid = self.get_property('src_pid', int)
        return self.src_pid

    def get_dst_pid(self) -> Optional[int]:
        self.dst_pid = self.get_property('dst_pid', int)
        return self.dst_pid

    def get_ipc_type(self) -> Optional[str]:
        self.ipc_type = self.get_property('ipc_type', str)
        return self.ipc_type

    def get_ipc_creator(self) -> Optional['PV']:
        self.created_ipc = self.get_edge("created_ipc", ProcessView)
        return self.created_ipc

    def get_ipc_recipient(self) -> Optional['PV']:
        self.received_ipc = self.get_edge("received_ipc", ProcessView)
        return self.received_ipc


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

    cur_user_id = cur_root.get_user_id()
    cur_auid = cur_root.get_auid()

    if cur_user_id is not None:
        user_ids.add(cur_user_id)
    if cur_auid is not None:
        auids.add(cur_auid)

    return get_uid_auid_lineage(cur_root.get_parent(), user_ids, auids)


class SshAgentAccessLineageAuidOrUidMismatch(Analyzer):
    # Look for IPC access where the target is ssh-agent
    def get_queries(self) -> OneOrMany[InterProcessCommunicationQuery]:
        return (
            # Query to check for mismatch of uid
            InterProcessCommunicationQuery()
            .with_ipc_creator(
                ProcessQuery().with_user_id()
            )
            .with_ipc_recipient(
                ProcessQuery()
                    .with_user_id()
                    .with_process_name(eq='ssh-agent')
                    .with_process_name(eq='sshd')
            ),
            # Query to check for mismatch of auid
            InterProcessCommunicationQuery()
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

    def on_response(self, response: InterProcessCommunicationView, output: Any):
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



