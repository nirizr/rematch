import idaapi
import idautils

from .annotation import Annotation


class AssemblyAnnotation(Annotation):
  type = 'assembly'

  def _data(self):
    flow_chart = idaapi.FlowChart(idaapi.get_func(self.offset))

    nodes = {}
    for node in flow_chart:
      assembly = [idaapi.generate_disasm_line(ea)
                    for ea in idautils.Heads(node.startEA, node.endEA)]
      successive_nodes = [succ.id for succ in node.succs()]
      serialized_node = {'id': node.id, 'type': node.type,
                         'start': node.startEA, 'end': node.endEA,
                         'successive': successive_nodes, 'assembly': assembly}
      nodes[node.id] = serialized_node

    return nodes
