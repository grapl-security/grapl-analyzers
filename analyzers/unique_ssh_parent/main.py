import os
from typing import Any, Type

import redis
from grapl_analyzerlib.analyzer import Analyzer, OneOrMany, A
from grapl_analyzerlib.counters import ParentChildCounter
from grapl_analyzerlib.entities import ProcessQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Not
from pydgraph import DgraphClient

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
        return [
            ("key", str),
            ("src_pid", int),
            ("dst_pid", int),
            ("ipc_type", str),
        ]

    def get_edge_tuples(self) -> List[Tuple[str, Union[List[Type[V]], Type[V]]]]:
        return [
            ("created_ipc", ProcessView),
            ("received_ipc", ProcessView),
        ]


    @staticmethod
    def get_edges() -> List[Tuple[str, Union[List[Type[V]], Type[V]]]]:
        return [
            ("created_ipc", ProcessView),
            ("received_ipc", ProcessView),
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
