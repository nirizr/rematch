import idaapi


class NetNode(object):
  @property
  def _nn(self):
    return idaapi.netnode("$rematch", 0, True)

  @property
  def bound_file_id(self):
    bound_file_id = self._nn.hashstr('bound_file_id')
    if not bound_file_id:
      return bound_file_id

    return int(bound_file_id)

  @bound_file_id.setter
  def bound_file_id(self, file_id):
    return self._nn.hashset("bound_file_id", str(file_id))

  @bound_file_id.deleter
  def bound_file_id(self):
    return self._nn.hashdel("bound_file_id")


netnode = NetNode()
