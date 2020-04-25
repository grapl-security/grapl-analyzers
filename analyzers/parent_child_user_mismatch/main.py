from typing import *

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.execution import ExecutionHit
from grapl_analyzerlib.prelude import ProcessQuery, ProcessView


try:
    from grapl_os_user_analyzer_plugin.user_id_assumption_node import UserIdAssumptionView, UserIdAssumptionQuery
    __should_load = True
except ModuleNotFoundError as e:
    print(f"WARN: {e}")
    __should_load = False

def load_analyzer():

    def with_assumed_user_id(process: ProcessQuery) -> ProcessQuery:
        # The ssh_process must have an associated user id
        (
            UserIdAssumptionQuery()
            .with_assuming_process(process)
            .with_user_id()
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


    class ParentChildUserMismatch(Analyzer):

        def get_queries(self) -> OneOrMany[ProcessQuery]:

            parent = with_assumed_user_id(ProcessQuery())
            child = with_assumed_user_id(ProcessQuery())
            child.with_parent(parent)

            return (
                child
             )

        def on_response(self, child: ProcessView, output: Any):
            asset_id = child.get_asset().get_hostname()

            parent = child.get_parent()

            child_user_id = get_user_id(child)
            parent_user_id = get_user_id(parent)

            if child_user_id != parent_user_id:

                output.send(
                    ExecutionHit(
                        analyzer_name="Parent Child User Mismatch",
                        node_view=child,
                        risk_score=25,
                        lenses=asset_id,
                    )
                )


if __should_load:
    load_analyzer()
