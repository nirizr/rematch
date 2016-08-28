from . import base
from ..dialogs.project import AddProjectDialog, AddFileDialog

from .. import netnode


class AddProjectAction(base.AuthAction):
  name = "&Add project"
  group = "Project"

  @staticmethod
  def activate(ctx):
    data, response, accepted = AddProjectDialog().get()

    if not accepted:
      return

    name, description, private, bind_current = data
    if bind_current:
      netnode.bound_file_id = response['id']


class AddFileAction(base.UnboundFileAction):
  name = "&Add file"
  group = "Project"

  @staticmethod
  def activate(ctx):
    response = AddFileDialog().get_response()
    if not response:
      return

    netnode.bound_file_id = response['id']
    # TODO: search for files with the same hash
