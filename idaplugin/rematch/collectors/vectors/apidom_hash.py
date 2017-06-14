from ida_gdl import FlowChart
from ida_idp import is_call_insn
from idaapi import get_func

from . import vector
from collections import defaultdict


class ApiDomintorHashVector(vector.Vector):
  type = 'apidom_hash'
  type_version = 0

  @classmethod
  def data(cls, offset):
    # iterate over the function's basic blocks
    flwchrt = FlowChart(get_func(offset))
    bbcall = defaultdict(list)

    for blck in flwchrt:
      start = blck.startEA
      curr_ea = start
      end = blck.endEA

      # bucketsize every basic block

      # TODO XXX
      # find a decent way to get imports
      # maybe a helper function instead
      # of inlining it here.

      bbinsn = []
      while curr_ea < end:
        bbinsn.append(GetMnem(curr_ea))  # noqa: F821

        if is_call_insn(curr_ea):
          bbcall[start].append(bbinsn)

        curr_ea = NextHead(curr_ea)  # noqa: F821
    return bbcall
