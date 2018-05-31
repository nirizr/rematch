import ida_gdl
import ida_funcs
import ida_lines
import idautils

from . import annotation


class PositionalAnnotation(annotation.Annotation):
  type = 'positional'

  @staticmethod
  def data(offset):
    func = ida_funcs.get_func(offset)

    def clean(asm):
      asm = ida_lines.tag_remove(asm)
      asm = asm.split(';', 1)[0]
      asm.strip()
      return asm

    # make sure only nodes inside the function are accounted for
    # this solves cascaded functions (when multiple functions share same ends)
    def node_contained(node):
      return (ida_funcs.func_contains(func, node.startEA) and
              ida_funcs.func_contains(func, node.endEA - 1))
    nodes = filter(node_contained, ida_gdl.FlowChart(func))
    node_ids = map(lambda n: n.id, nodes)

    nodes_data = []
    for node in nodes:
      assembly = [clean(ida_lines.generate_disasm_line(ea))
                    for ea in idautils.Heads(node.startEA, node.endEA)]
      successive_nodes = [succ.id
                            for succ in node.succs()
                            if succ.id in node_ids]
      serialized_node = {'id': node.id, 'start': node.startEA,
                         'end': node.endEA, 'successive': successive_nodes,
                         'assembly': assembly}
      nodes_data.append(serialized_node)

    return nodes_data

  @staticmethod
  def apply(offset, data):
    del offset
    del data
