from . import base
from ..dialogs.project import AddProjectDialog, AddFileDialog

from .. import netnode
from .. import network


class AddProjectAction(base.AuthAction):
  name = "&Add project"
  group = "Project"
  dialog = AddProjectDialog

  @staticmethod
  def submit_handler(name, description, private, bind_current):
    data = {'name': name, 'description': description, 'private': private,
            'files': []}

    if bind_current:
      data['files'].append(netnode.bound_file_id)

    return network.QueryWorker("POST", "collab/projects/", params=data,
                               json=True)

  @classmethod
  def response_handler(cls, response):
    del response
    cls.force_update()
    return True


class AddFileAction(base.UnboundFileAction):
  name = "&Add file"
  group = "Project"
  dialog = AddFileDialog

  @staticmethod
  def submit_handler(project, name, md5hash, description, shareidb):
    # TODO: search for files with the same hash
    data = {'project': project, 'name': name, 'md5hash': md5hash,
            'description': description, 'instances': []}

    if shareidb:
      # TODO: uploadfile
      pass

    return network.QueryWorker("POST", "collab/files/", params=data,
                               json=True)

  @classmethod
  def response_handler(cls, response):
    netnode.bound_file_id = response['id']
    cls.force_update()
    return True
