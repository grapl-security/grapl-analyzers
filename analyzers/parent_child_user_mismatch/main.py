from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.entities import ProcessQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.querying import Viewable, Queryable


class ParentChildUserMismatch(Analyzer):

    def get_queries(self) -> OneOrMany[Queryable]:
        # TODO: Whitelist based on parent, like sudo
        return (
            ProcessQuery()
            .with_user_id()
            .with_parent(
                ProcessQuery()
                .with_user_id()
            ),
            ProcessQuery()
            .with_auid()
            .with_parent(
                ProcessQuery()
                .with_auid()
            ),
         )

    def on_response(self, child: ProcessView, output: Any):
        parent = child.get_parent()

        uid_mismatch = False
        auid_mismatch = False

        if parent.get_user_id() is not None and child.get_user_id() is not None:
            uid_mismatch = parent.get_user_id() != child.get_user_id()

        if parent.get_auid() is not None and child.get_auid() is not None:
            auid_mismatch = parent.get_auid() != child.get_auid()

        if uid_mismatch or auid_mismatch:

            output.send(
                ExecutionHit(
                    analyzer_name="Parent Child User Mismatch",
                    node_view=child,
                    risk_score=25,
                )
            )
