from ..idasix import QtCore
import idautils

from ..dialogs.upload import UploadDialog

from .. import instances
from .. import network, netnode, log
from . import base

import hashlib


class UploadAction(base.BoundFileAction):
  name = "&Upload"
  dialog = UploadDialog

  def __init__(self, *args, **kwargs):
    super(UploadAction, self).__init__(*args, **kwargs)
    self.functions = None
    self.file_version_id = None
    self.instance_set = []

    self.timer = None

  def clean(self):
    if self.timer:
      self.timer.stop()
    self.timer = None

  def cancel(self):
    log('upload_action').info("upload action cancelled")
    self.clean()

  @staticmethod
  def calc_file_version_hash():
    version_obj = {}
    version_obj['functions'] = {offset: list(idautils.Chunks(offset))
                                  for offset in idautils.Functions()}
    version_str = repr(version_obj)
    version_hash = hashlib.md5(version_str).hexdigest()

    log('upload_action').info("file version string: %s", version_str)
    log('upload_action').info("file version hash: %s", version_hash)
    return version_hash

  def submit_handler(self):
    file_version_hash = self.calc_file_version_hash()
    uri = "collab/files/{}/file_version/{}/".format(netnode.bound_file_id,
                                                    file_version_hash)
    return network.QueryWorker("POST", uri, json=True)

  def response_handler(self, file_version):
    self.file_version_id = file_version['id']

    if file_version['newly_created']:
      return self.start_upload()
    else:
      print("TODO: version up to date, nothing to do here")
      return True

  def start_upload(self):
    log('upload_action').info("Data upload started")

    self.functions = set(idautils.Functions())
    self.ui.setRange(0, len(self.functions))

    self.timer = QtCore.QTimer()
    self.timer.timeout.connect(self.perform_upload)
    self.timer.start(0)

    return False

  def perform_upload(self):
    if not self.functions:
      return

    # pop a function, serialize and add to the ready set
    offset = self.functions.pop()
    func = instances.FunctionInstance(self.file_version_id, offset)
    self.instance_set.append(func.serialize())

    # if ready set contains 100 or more functions, or if we just poped the last
    # function clear and upload entire ready set to the server.
    if len(self.instance_set) >= 100 or not self.functions:
      q = network.QueryWorker("POST", "collab/instances/",
                              params=self.instance_set, json=True)
      q.start(self.progress_advance)
      self.instance_set = []
      self.ui.setMaximum(self.ui.maximum() + 1)
    self.progress_advance()

  def progress_advance(self, result=None):
    del result
    self.ui.advance()

  def accept(self):
    log('upload_action').info("Data upload completed successfully")
    self.clean()

    print("TODO: upload completed successfully")
