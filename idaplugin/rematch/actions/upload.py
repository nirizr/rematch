from ..idasix import QtCore
import idautils

from ..dialogs.upload import UploadDialog

from ..collectors.annotations import DependencyAnnotation
from ..instances import FunctionInstance, UniversalInstance
from .. import network, netnode, log
from . import base

import hashlib


class UploadAction(base.BoundFileAction):
  name = "&Upload"
  dialog = UploadDialog

  def __init__(self, *args, **kwargs):
    super(UploadAction, self).__init__(*args, **kwargs)
    self.instances = None
    self.file_version_id = None
    self.force_update = None
    self.upload_annotations = None
    self.instance_objs = []

    self.delayed_queries = []

    self.timer = QtCore.QTimer()

  def clean(self):
    self.timer.stop()
    try:
      self.timer.timeout.disconnect()
    except TypeError:
      pass

    for delayed in self.delayed_queries:
      delayed.cancel()
    self.delayed_queries = []

  @staticmethod
  def calc_file_version_hash():
    version_obj = []
    version_obj.append(('functions', [(offset, list(idautils.Chunks(offset)))
                                        for offset in idautils.Functions()]))
    # TODO: This is a little hackish way of getting the version of all vectors
    # of an instance. cannot make version a classmethod because vector sets are
    # only built by __init__ methods
    func_vector_versions = FunctionInstance(None, None).version()
    version_obj.append(('function_vector_versions', func_vector_versions))
    # TODO: Add function annotations as part of the version, because they're
    # also changing.
    # TODO: Add universal instance related versions

    version_str = repr(version_obj)
    version_hash = hashlib.md5(version_str).hexdigest()

    log('upload_action').info("file version string: %s", version_str)
    log('upload_action').info("file version hash: %s", version_hash)
    return version_hash

  def submit_handler(self, force_update, upload_annotations):
    self.upload_annotations = upload_annotations

    self.ui.statusLbl.setText("Uploading...")
    self.ui.statusLbl.setToolTip("")
    self.ui.statusLbl.setStyleSheet("color: black;")

    endpoint = "collab/file_versions/"
    if force_update:
      endpoint += "?force=True"
    params = {'file': netnode.bound_file_id, 'complete': False,
              'md5hash': self.calc_file_version_hash()}
    return network.QueryWorker("POST", endpoint, json=True, params=params)

  def response_handler(self, file_version):
    self.file_version_id = file_version['id']

    # if we successfully created a file_version we will start the data upload
    self.start_upload()

  def start_upload(self):
    log('upload_action').info("Data upload started")

    # TODO: Is this too slow? should we move this to perform_upload? or into a
    # generator?
    self.instances = set((FunctionInstance, f) for f in idautils.Functions())
    self.instances.add((UniversalInstance, (s[0] for s in idautils.Structs())))

    self.ui.increase_maximum(len(self.instances))

    self.timer.timeout.connect(self.perform_upload)
    self.timer.start(0)

  def perform_upload(self):
    if not self.instances:
      return

    # pop a function, serialize and add to the ready set
    instance_cls, instance_data = self.instances.pop()
    instance_obj = instance_cls(self.file_version_id, instance_data)
    self.instance_objs.append(instance_obj.serialize(self.upload_annotations))

    # if ready set contains 100 or more instances, or if we just poped the last
    # function clear and upload entire ready set to the server.
    url_params = "?force_update=true" if self.force_update else ""
    if len(self.instance_objs) >= 100 or not self.instances:
      q = network.QueryWorker("POST", "collab/instances/" + url_params,
                              params=self.instance_objs, json=True)
      q.start(self.progress_advance)
      self.delayed_queries.append(q)

      self.instance_objs = []
      self.ui.increase_maximum()
    self.progress_advance()

  def progress_advance(self, result=None):
    del result
    self.ui.advance()

  def accept_handler(self):
    self.clean()

    # TODO: make these delayed queries?
    # Upload dependencies if there are any
    dependencies = DependencyAnnotation.get_dependencies()
    if dependencies:
      network.query("POST", "collab/dependencies/", json=True,
                    params=dependencies)

    # mark file version as complete
    endpoint = "collab/file_versions/{}/".format(self.file_version_id)
    network.query("PATCH", endpoint, json=True, params={'complete': True})

    log('upload_action').info("Data upload completed successfully")

  def reject_handler(self):
    self.clean()
    log('upload_action').info("upload action cancelled")
