
import unittest

from queue import Queue

from copy import deepcopy
from typing import Optional

from grapl_analyzerlib.entities import NodeView
from grapl_analyzerlib.execution import ExecutionHit
from pydgraph import DgraphClient

from analyzers.suspicious_svchost.main import analyzer


class TestSuspiciousSvchost(unittest.TestCase):

    def setUp(self) -> None:
        self.local_mg = init_local_dgraph()
        self.node_view = populate_signature('hardcoded-node-key')

    def test_suspicious_svchost_hit(self):
        result = exec_sync(analyzer, self.local_mg, self.node_view)
        assert isinstance(result, ExecutionHit)

    def test_suspicious_svchost_miss(self):
        benign_view = deepcopy(self.node_view)
        benign_view.node_key = "some-other-key"

        result = exec_sync(analyzer, self.local_mg, benign_view)

        assert result is None


if __name__ == "__main__":
    unittest.main()



def exec_sync(analyzer, client, node_view) -> Optional[ExecutionHit]:
    pass





def init_local_dgraph() -> DgraphClient:
    pass

def populate_signature(node_key) -> NodeView:
    raise NotImplementedError