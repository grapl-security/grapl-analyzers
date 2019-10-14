import os

from typing import Any, Optional

import redis

from grapl_analyzerlib.execution import ExecutionHit, ExecutionComplete
from pydgraph import DgraphClient
from grapl_analyzerlib.entities import ProcessQuery, SubgraphView, FileQuery, ProcessView, NodeView


def analyzer(client: DgraphClient, node: NodeView, sender: Any):
    return