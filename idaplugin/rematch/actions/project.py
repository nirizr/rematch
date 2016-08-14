import idaapi

from . import base
from ..dialogs.project import AddProjectDialog, AddFileDialog


class AddProjectAction(base.AuthAction):
  name = "&Add project"
  group = "Project"

  def activate(self, ctx):
    data, response, accepted = AddProjectDialog().get()

    if not accepted:
      return

    name, description, private, bind_current = data
    if bind_current:
      nn = idaapi.netnode("$rematch", 0, True)
      nn.hashset('bound_project_id', str(response['id']))


class AddFileAction(base.UnboundFileAction):
  name = "&Add file"
  group = "Project"

  def activate(self, ctx):
    response = AddFileDialog().get_response()
    if not response:
      return

    nn = idaapi.netnode("$rematch", 0, True)
    nn.hashset('bound_file_id', str(response['id']))
    # search for files with the same hash
