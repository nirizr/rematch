from decimal import Decimal
import json

import networkx as nx
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
                         "solely on graph properties, with no consideration of "
                         "data.")
  qs = np.sqrt(np.array([Decimal(1), Decimal(2), Decimal(3), Decimal(5),
                         Decimal(7)]))

  @classmethod
  def hash_func(cls, graph):
    # JSON only allows strings as keys, so we gotta convery them back to ints
    # as networkx requires
    graph = {int(k): v for k, v in json.loads(graph).items()}
    g = nx.convert.from_dict_of_lists(graph, create_using=nx.DiGraph)
    tsort = nx.algorithms.dag.topological_sort(g)

    embs = np.array([(tsort.index(s), g.in_degree[s], g.out_degree[s],
                      g.in_degree[d], g.out_degree[d]) for s, d in graph.nodes])

    embs *= cls.qs

    embs = 1 / np.sqrt(embs)

    embs = embs.sum()

    return embs
