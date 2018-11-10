import ida_funcs
import ida_gdl

from . import vector


class BasicBlockAdjacencyVector(vector.Vector):
  type = 'basicblock_adjacency'
  type_version = 0

  def data(self):
    adjacencies = {}
    seen = set()

    for node in ida_gdl.FlowChart(ida_funcs.get_func(self.offset)):
      if node.id in seen:
        continue
      seen.add(node.id)

      adjacencies[node.id] = [succ.id for succ in node.succs()]

    return adjacencies
