from collect import defaultdict
import ida_gdl
import idaapi

from . import vector


class MDIndexVector(vector.Vector):
  type = 'MDIndex_Hash'
  type_version = 0

  @classmethod
  def data(cls, offset):
    # we're assuming offset is actually a function
    # which has boundaries
    # this goes to every other Hashing Vector
    # so this assumption is reasonable.
    fn = idaapi.get_func(offset)
    bbs = ida_gdl.FlowChart(fn)

    bbset = defaultdict(dict)

    for bb in bbs:
      if bb not in bbset:
        bbset[bb] = {'in': 0, 'out': 0}
      bbset[bb]['in'] += 1

      chunks = [chunk for chunk in bb.succs()]
      if chunks[-1] not in bbset:
        bbset[bb] = {'in': 0, 'out': 0}
      bbset[bb]['out'] += 1
