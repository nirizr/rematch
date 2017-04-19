import ida_gdl
import ida_funcs
import ida_lines
import idautils

from . import annotation


class AssemblyAnnotation(annotation.Annotation):
  type = 'assembly'

  @classmethod
  def _data(cls, offset):
    flow_chart = ida_gdl.FlowChart(ida_funcs.get_func(offset))

    nodes = {}
    for node in flow_chart:
      assembly = [ida_lines.generate_disasm_line(ea)
                    for ea in idautils.Heads(node.startEA, node.endEA)]
      successive_nodes = [succ.id for succ in node.succs()]
      serialized_node = {'id': node.id, 'type': node.type,
                         'start': node.startEA, 'end': node.endEA,
                         'successive': successive_nodes, 'assembly': assembly}
      nodes[node.id] = serialized_node

    return nodes

  @classmethod
  def apply(self, offset, data):
    del offset
    del data
