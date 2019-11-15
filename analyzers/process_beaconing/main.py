# import os
# from typing import *
#
# import redis as redis
# import scipy.stats as ss
# from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
# from grapl_analyzerlib.execution import ExecutionHit
# from grapl_analyzerlib.prelude import ProcessQuery, ProcessView
#
# COUNTCACHE_ADDR = os.environ['COUNTCACHE_ADDR']
# COUNTCACHE_PORT = int(os.environ['COUNTCACHE_PORT'])
#
# r = redis.Redis(host=COUNTCACHE_ADDR, port=COUNTCACHE_PORT, db=0, decode_responses=True)
#
#
# def diff_timestamps(timestamps: Sequence[int]) -> List[int]:
#     diffs = []
#     timestamp_iter = iter(timestamps)
#     for timestamp_a in timestamp_iter:
#         try:
#             timestamp_b = next(timestamp_iter)
#         except StopIteration:
#             break
#         diffs.append(timestamp_a - timestamp_b)
#     return diffs
#
#
# def is_beaconing(timestamps: Sequence[int]) -> Optional[bool]:
#     sorted_timestamps = list(timestamps)
#     sorted_timestamps.sort(reverse=True)
#
#     if len(timestamps) < 10:
#         return None
#
#     diffs = diff_timestamps(timestamps)
#
#     _ks, d = ss.kstest(
#         diffs,
#         ss.randint.cdf,
#         args=(sorted_timestamps[0], sorted_timestamps[-1])
#     )
#     if d != d:
#         return d >= 0.5
#     return None
#
#
# class ProcessBeaconing(Analyzer):
#
#     def get_queries(self) -> OneOrMany[ProcessQuery]:
#         return (
#             ProcessQuery()
#             .with_created_connections()
#         )
#
#     def on_response(self, response: ProcessView, output: Any):
#         timestamps = [cf.get_timestamp() for cf in response.get_created_connections()]
#
#         if is_beaconing(timestamps):
#             output.send(
#                 ExecutionHit(
#                     analyzer_name="Process Beaconing",
#                     node_view=response,
#                     risk_score=25,
#                 )
#             )
