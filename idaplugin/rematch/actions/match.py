from ..idasix import QtCore, QtWidgets
import idautils

from ..dialogs.match import MatchDialog

from .. import instances
from .. import network, netnode
from . import base


class MatchAction(base.BoundFileAction):
  name = "&Match"
  dialog = MatchDialog

  def __init__(self, *args, **kwargs):
    super(MatchAction, self).__init__(*args, **kwargs)
    self.function_gen = None
    self.pbar = None
    self.timer = None
    self.task_id = None
    self.instance_set = []

    self.source = None
    self.source_single = None
    self.source_range = None
    self.target = None
    self.target_project = None
    self.target_file = None
    self.methods = None

  def get_functions(self):
    if self.source == 'idb':
      return set(idautils.Functions())
    elif self.source == 'user':
      raise NotImplementedError("All user functions are not currently "
                                "supported as source value.")
    elif self.source == 'single':
      return [self.source_single]
    elif self.source == 'range':
      return set(idautils.Functions(self.source_range[0],
                                    self.source_range[1]))

    raise ValueError("Invalid source value received from MatchDialog: {}"
                     "".format(self.source))

  def submit_handler(self, source, source_single, source_range, target,
                     target_project, target_file, methods):
    self.source = source
    self.source_single = source_single
    self.source_range = source_range
    self.target = target
    self.target_project = target_project if target == 'project' else None
    self.target_file = target_file if target == 'file' else None
    self.methods = methods

    functions = self.get_functions()
    if not functions:
      return False

    self.function_gen = enumerate(functions)
    self.pbar = QtWidgets.QProgressDialog()
    self.pbar.setLabelText("Processing IDB... You may continue working,\nbut "
                           "please avoid making any ground-breaking changes.")
    self.pbar.setRange(0, len(functions))
    self.pbar.setValue(0)
    self.pbar.canceled.connect(self.cancel_upload)
    self.pbar.rejected.connect(self.reject_upload)
    self.pbar.accepted.connect(self.accept_upload)

    self.timer = QtCore.QTimer()
    self.timer.timeout.connect(self.perform_upload)
    self.timer.start(0)

    return True

  def perform_upload(self):
    try:
      i, offset = self.function_gen.next()
    except StopIteration:
      self.timer.stop()
      return

    try:
      func = instances.FunctionInstance(netnode.bound_file_id, offset)
      self.instance_set.append(func.serialize())

      if len(self.instance_set) >= 100:
        network.delayed_query("POST", "collab/instances/",
                              params=self.instance_set, json=True,
                              callback=self.progress_advance)
        self.instance_set = []
        self.pbar.setMaximum(self.pbar.maximum() + 1)
      self.progress_advance()
    except Exception:
      self.cancel_upload()
      raise

  def progress_advance(self, result=None):
    del result
    new_value = self.pbar.value() + 1
    self.pbar.setValue(new_value)
    if new_value >= self.pbar.maximum():
      self.pbar.accept()

  def cancel_upload(self):
    self.timer.stop()
    self.timer = None
    self.pbar = None

  def reject_upload(self):
    self.cancel_upload()

  def accept_upload(self):
    self.cancel_upload()

    if self.source == 'idb':
      self.source_range = [None, None]
    elif self.source == 'single':
      self.source_range = [self.source_single, self.source_single]
    elif self.source == 'range':
      pass
    else:
      raise NotImplementedError("Unsupported source type encountered in task "
                                "creation")

    params = {'source_file': netnode.bound_file_id,
              'source_start': self.source_range[0],
              'source_end': self.source_range[1],
              'target_project': self.target_project,
              'target_file': self.target_file,
              'source': self.source, 'methods': self.methods}
    r = network.query("POST", "collab/tasks/", params=params, json=True)
    self.task_id = r['id']

    self.pbar = QtWidgets.QProgressDialog()
    self.pbar.setLabelText("Waiting for remote matching... You may continue "
                           "working without any limitations.")
    self.pbar.setRange(0, int(r['progress_max']) if r['progress_max'] else 0)
    self.pbar.setValue(int(r['progress']))
    self.pbar.canceled.connect(self.cancel_task)
    self.pbar.rejected.connect(self.reject_task)
    self.pbar.accepted.connect(self.accept_task)
    self.pbar.show()

    self.timer = QtCore.QTimer()
    self.timer.timeout.connect(self.perform_task)
    self.timer.start(1000)

  def perform_task(self):
    try:
      r = network.query("GET", "collab/tasks/{}/".format(self.task_id),
                        json=True)

      progress_max = int(r['progress_max']) if r['progress_max'] else None
      progress = int(r['progress'])
      status = r['status']
      if status == 'failed':
        self.pbar.reject()
      elif progress_max:
        self.pbar.setMaximum(progress_max)
        if progress >= progress_max:
          self.pbar.accept()
        else:
          self.pbar.setValue(progress)
    except Exception:
      self.cancel_task()
      raise

  def cancel_task(self):
    self.timer.stop()
    self.timer = None
    self.pbar = None

  def reject_task(self):
    self.cancel_task()

  def accept_task(self):
    self.cancel_task()
