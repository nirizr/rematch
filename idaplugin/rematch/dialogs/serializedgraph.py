import ida_graph


class SerializedGraphDialog(ida_graph.GraphViewer):
  def __init__(self, *args, **kwargs):
    title = "Remote Function"
    super(SerializedGraphDialog, self).__init__(title, *args, **kwargs)
    self.nodes = {}

  def SetNodes(self, nodes):  # noqa: N802
    self.nodes = nodes
    self.Refresh()

  def OnGetText(self, node_id):  # noqa: N802
    """
    Triggered when the graph viewer wants the text and color for a given node.
    This callback is triggered one time for a given node (the value will be
    cached and used later without calling Python). When you call refresh then
    again this callback will be called for each node.

    This callback is mandatory.

    @return: Return a string to describe the node text or return a tuple
    (node_text, node_color) to describe both text and color
    """
    return self[node_id]

  @staticmethod
  def OnSelect(node_id):  # noqa: N802
    """
    Triggered when a node is being selected
    @return: Return True to allow the node to be selected or False to disallow
             node selection change
    """
    del node_id
    return True

  @staticmethod
  def OnClick(node_id):  # noqa: N802
    """
    Triggered when a node is clicked
    @return: False to ignore the click and True otherwise
    """
    del node_id
    return True

  @staticmethod
  def OnDblClick(node_id):  # noqa: N802
    """
    Triggerd when a node is double-clicked.
    @return: False to ignore the click and True otherwise
    """
    del node_id
    return True

  def OnRefresh(self):  # noqa: N802
    """
    Event called when the graph is refreshed or first created.
    From this event you are supposed to create nodes and edges.
    This callback is mandatory.
    @note: ***It is important to clear previous nodes before adding nodes.***
    @return: Returning True tells the graph viewer to use the items. Otherwise
    old items will be used.
    """
    self.Clear()

    # create nodes
    local_ids = {}
    for node in self.nodes:
      node_text = "\n".join(node['assembly'])
      local_id = self.AddNode((str(node_text), 0xffffff))
      local_ids[node['id']] = local_id

    for node in self.nodes:
      local_id = local_ids[node['id']]
      for succ in node['successive']:
        successive_id = local_ids[succ]
        self.AddEdge(local_id, successive_id)
    return True
