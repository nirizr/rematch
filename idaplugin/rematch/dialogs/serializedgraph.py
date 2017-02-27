import idaapi


class SerializedGraphDialog(idaapi.GraphViewer):
  def __init__(self, *args, **kwargs):
    title = "Remote Function"
    super(SerializedGraphDialog, self).__init__(title, *args, **kwargs)
    self.nodes = {}

  def SetNodes(self, nodes):
    self.nodes = nodes
    self.Refresh()

  def OnGetText(self, node_id):
    return self[node_id]

  def OnRefresh(self):
    self.Clear()

    # create nodes
    local_ids = {}
    for node in self.nodes.values():
      node_text = "\n".join(node['assembly'])
      local_id = self.AddNode((str(node_text), 0xffffff))
      local_ids[node['id']] = local_id

    for node in self.nodes.values():
      local_id = local_ids[node['id']]
      for succ in node['successive']:
        successive_id = local_ids[succ]
        self.AddEdge(local_id, successive_id)
    return True
