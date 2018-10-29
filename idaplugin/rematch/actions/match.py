from ..idasix import QtCore, QtWidgets

from ..dialogs.match import MatchDialog
from ..dialogs.matchresult import MatchResultDialog

from .upload import UploadAction

from .. import network, netnode, log
from . import base

import json


class MatchAction(base.BoundFileAction):
  name = "&Match"
  dialog = MatchDialog

  def __init__(self, *args, **kwargs):
    super(MatchAction, self).__init__(*args, **kwargs)
    self.instances = None
    self.results = None
    self.task_id = None
    self.file_version_id = None
    self.instance_objs = []

    self.source = None
    self.source_single = None
    self.source_range = None
    self.target = None
    self.target_project = None
    self.target_file = None
    self.strategy = None
    self.matchers = None
    self.seen = None

    self.delayed_queries = []

    # TODO: use a single PBD and reset() it
    self.pbar = None
    self.timer = QtCore.QTimer()

  def clean(self):
    self.timer.stop()
    try:
      self.timer.timeout.disconnect()
    except TypeError:
      pass

    try:
      self.pbar.accepted.disconnect()
    except TypeError:
      pass
    self.pbar.close()
    self.pbar = None

    for delayed in self.delayed_queries:
      delayed.cancel()
    self.delayed_queries = []

  def cancel(self):
    log('match_action').info("match action cancelled by user")
    self.clean()

  def submit_handler(self, source, source_single, source_range, target,
                     target_project, target_file, strategy, matchers):
    self.source = source
    self.source_single = source_single
    self.source_range = source_range
    self.target = target
    self.target_project = target_project if target == 'project' else None
    self.target_file = target_file if target == 'file' else None
    self.strategy = strategy
    self.matchers = matchers

    file_version_hash = UploadAction.calc_file_version_hash()
    uri = "collab/files/{}/file_version/{}/".format(netnode.bound_file_id,
                                                    file_version_hash)
    return network.QueryWorker("GET", uri, json=True)

  def response_handler(self, file_version):
    self.file_version_id = file_version['id']

    self.start_task()
    return True

  def start_task(self):
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
              'source_file_version': self.file_version_id,
              'source_start': self.source_range[0],
              'source_end': self.source_range[1],
              'target_project': self.target_project,
              'target_file': self.target_file,
              'source': self.source, 'strategy': self.strategy,
              'matchers': json.dumps(self.matchers)}
    r = network.query("POST", "collab/tasks/", params=params, json=True)
    self.task_id = r['id']

    self.pbar = QtWidgets.QProgressDialog()
    self.pbar.canceled.connect(self.cancel)
    self.pbar.rejected.connect(self.cancel)
    self.pbar.setLabelText("Waiting for remote matching... You may continue "
                           "working without any limitations.")
    self.pbar.setRange(0, int(r['progress_max']) if r['progress_max'] else 0)
    self.pbar.setValue(int(r['progress']))
    self.pbar.accepted.connect(self.accept_task)
    self.pbar.show()

    self.timer.timeout.connect(self.perform_task)
    self.timer.start(200)

  def perform_task(self):
    try:
      r = network.query("GET", "collab/tasks/{}/".format(self.task_id),
                        json=True)

      progress_max = int(r['progress_max']) if r['progress_max'] else None
      progress = int(r['progress'])
      status = r['status']
      if status == 'failed':
        self.clean()
        log('match_action').error("Task failed!")
      elif progress_max:
        self.pbar.setMaximum(progress_max)
        if progress >= progress_max:
          self.pbar.accept()
        else:
          self.pbar.setValue(progress)
    except Exception:
      self.clean()
      log('match_action').exception("perform update failed")
      raise

  def accept_task(self):
    log('match_action').info("Remote task completed successfully")

    self.clean()

    ResultAction(self.task_id).activate()
