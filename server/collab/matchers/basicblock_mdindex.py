from decimal import Decimal
import json

import networkx as nx
from tarjan import tarjan_recursive as tarjan
import numpy as np

from . import hash_matcher


class BasicBlockMDIndexMatcher(hash_matcher.HashMatcher):
  vector_type = 'basicblock_adjacency'
  match_type = 'basicblock_mdindex_hash'
  matcher_name = "Basic Block MDIndex Hash"
  matcher_description = ("Exact matches for functions with identical MDIndex "
                         "hash values over basic block graphs. MDIndex is a "
                         "collection of attributes selected by Zynamics, "
                         "mostly known for BinDiff, to describe graphs based "
                         "solely on graph properties, with no consideration "
                         "of data.")
  qs = np.sqrt(np.array([Decimal(1), Decimal(2), Decimal(3), Decimal(5),
                         Decimal(7)]))

  @classmethod
  def hash_func(cls, adjacency):
    # JSON only allows strings as keys, so we gotta convert them back to ints
    # before we run tarjan's algorithm on the adjacency dict
    adjacency = {int(k): v for k, v in json.loads(adjacency).items()}
    graph = nx.convert.from_dict_of_lists(adjacency, create_using=nx.DiGraph)
    t_order = sum(tarjan(adjacency), [])

    embs = np.array([(t_order.index(s),
                      graph.in_degree[s], graph.out_degree[s],
                      graph.in_degree[d], graph.out_degree[d])
                      for s, d in graph.edges])

    return (1 / np.sqrt(np.dot(embs, cls.qs))).sum()
