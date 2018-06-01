import ida_funcs
import ida_gdl

from . import vector

from collections import defaultdict


class BasicBlockSizeHistVector(vector.Vector):
  type = 'basicblocksize_hist'
  type_version = 0

  def data(self):
    sizes_hist = defaultdict(int)
    seen = set()

    for node in ida_gdl.FlowChart(ida_funcs.get_func(self.offset)):
      if node.id in seen:
        continue
      seen.add(node.id)

      node_size = node.endEA - node.startEA
      sizes_hist[node_size] += 1

    if sum(sizes_hist.values()) < 5:
      return None

    return sizes_hist
