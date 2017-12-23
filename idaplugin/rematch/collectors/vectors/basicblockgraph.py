import ida_gdl
import ida_funcs

from . import vector


class BasicBlockGraphVector(vector.Vector):
  type = "basicblockgraph"
  type_version = 0

  def __init__(self, *args, **kwargs):
    super(BasicBlockGraphVector, self).__init__(*args, **kwargs)

    self.func = ida_funcs.get_func(self.offset)

    self.nodes = filter(self.node_contained, ida_gdl.FlowChart(self.func))
    self.node_ids = map(lambda n: n.id, self.nodes)

    self.seen_nodes = set()

  def data(self):

    # Assuming node #0 is the root node
    serialized_bbs = self.add_node(self.nodes[0])
    print(serialized_bbs)
    return serialized_bbs

  def add_node(self, node):
    if node.id in self.seen_nodes:
      return [self.token(node)]

    self.seen_nodes.add(node.id)
    print("{:x}: {}".format(node.startEA, self.token(node)))

    # get successive nodes ordered by thier own sizes
    sorted_succs = self.sort_nodes(node.succs())
    # get successive node sub-graphs ordered
    succ_values = map(self.add_node, sorted_succs)
    # merge all nodes together by order
    return sum(succ_values, [self.token(node)])

  def sort_nodes(self, nodes):
    return sorted(nodes, key=self.sort_key)

  @staticmethod
  def token(node):
    # alternatives: offset from start of function
    return node.endEA - node.startEA

  sort_key = token

  def node_contained(self, node):
    # make sure only nodes inside the function are accounted for
    # this solves cascaded functions (when multiple functions share same ends)
    return (ida_funcs.func_contains(self.func, node.startEA) and
            ida_funcs.func_contains(self.func, node.endEA - 1))
