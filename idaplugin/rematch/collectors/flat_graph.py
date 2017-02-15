import idaapi

from .vector import Vector


class FlatGraphVector(Vector):
  type = 'flatgraph_editdistance'
  type_version = 0

  def __init__(self, *args, **kwargs):
    super(FlatGraphVector, self).__init__(*args, **kwargs)
    self.flow_chart = idaapi.FlowChart(idaapi.get_func(self.offset))
    self.visited = set()
    self.items = list[self.flow_chart.size]

  def _bb_size(self, bb):
    if bb.endEA > bb.startEA:
      return bb.endEA - bb.startEA

    raise ValueError("while flattening graph, a basicblock that ends before "
                     "it starts encountered at {:x}".format(self.offset))

  def _bb_value(self, bb):
    # TODO: this should be something that's uncorellated with the order of
    #  basic blocks
    return self._bb_size(bb)

  def _append_bbs(self, *bbs):
    self.items.extend(map(self._bb_value, bbs))

  def _find_head(self):
    def is_head(bb):
      return len(bb.preds()) == 0

    heads = filter(is_head, self.flow_chart)
    if len(heads) == 1:
      return heads[0]

    msg = ("flattening graphs with head count other than 1 is not supported, "
           "got {} head-count for {:x}".format(len(heads), self.offset))
    raise ValueError(msg)

  def _sort_siblings(self, siblings):
    return sorted(siblings, key=self._bb_size)

  def _recurse_bb(self, bb):
    if bb in self.visited:
      return []

    self.visited.add(bb)
    siblings = self._sort_siblings(bb.succs())
    self._append_bbs(*siblings)

    for sibling in siblings:
      self._recurse_siblings(sibling)

  def _data(self):
    head = self._find_head()
    self._recurse_bb(head)
    return self.items
