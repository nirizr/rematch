import ida_gdl
import ida_funcs
import ida_lines
import ida_idaapi
import idautils

from math import log
import re

from . import annotation


class AssemblyAnnotation(annotation.Annotation):
  type = 'assembly'

  @staticmethod
  def data(offset):
    func = ida_funcs.get_func(offset)

    def clean(asm):
      """This removes markers of function offsets, including hidden variable
      length offsets that are of different length on 32 and 64 bit address IDA.
      Otherwise, IDA of different offset lengths will truncate incorrect number
      of bytes"""
      hex_chars = int(log(ida_idaapi.BADADDR + 1, 2) / 4)
      pattern = (r"\x01(.{1})\x01\([0-9a-zA-Z]{%s}([\w\s!@$?_]*?)\x02\1\x02\)"
                  "" % hex_chars)
      replace = "\x01\g<1>\g<2>\x02\g<1>"
      return re.sub(pattern, replace, asm)

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
      serialized_node = {'id': node.id, 'type': node.type,
                         'start': node.startEA, 'end': node.endEA,
                         'successive': successive_nodes, 'assembly': assembly}
      nodes_data.append(serialized_node)

    return nodes_data

  @staticmethod
  def apply(offset, data):
    del offset
    del data
