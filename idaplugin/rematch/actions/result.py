from ..idasix import QtCore

from ..dialogs.result import ResultDialog

from .. import network, log
from . import base


class ResultAction(base.BoundFileAction):
  name = "&Result"
  dialog = ResultDialog

  def __init__(self, task_id=None, *args, **kwargs):
    super(ResultAction, self).__init__(*args, **kwargs)
    self.instances = None
    self.results = None
    self.task_id = task_id
    self.file_version_id = None

    self.delayed_queries = []

    self.timer = QtCore.QTimer()

    # if we got a task id, lets start pulling results. Otherwise, we'll wait
    # for submit_handler to be called from ResultDialog
    if self.task_id:
      self.start_results()

  def submit_handler(self, task_id):
    self.task_id = task_id

    self.start_results()

  def start_results(self):
    self.ui.set_status("Receiving match results...")
    self.ui.progress.setRange(0, 3)  # 3 end points (locals, remotes, matches)
    self.pbar.setValue(0)
    self.pbar.accepted.connect(self.accept_results)

    self.seen = set()

    log('match_action').info("Result download started")
    locals_url = "collab/instances/?from_matches__task={}".format(self.task_id)
    q = network.QueryWorker("GET", locals_url, json=True, paginated=True)
    q.start(self.handle_locals)
    self.delayed_queries.append(q)

    remotes_url = "collab/instances/?to_matches__task={}".format(self.task_id)
    q = network.QueryWorker("GET", remotes_url, json=True, paginated=True)
    q.start(self.handle_remotes)
    self.delayed_queries.append(q)

    matches_url = "collab/matches/?task={}".format(self.task_id)
    q = network.QueryWorker("GET", matches_url, json=True, paginated=True)
    q.start(self.handle_matches)
    self.delayed_queries.append(q)

  def handle_locals(self, response):
    new_locals = {obj['id']: obj for obj in response['results']}
    self.results.add_locals(new_locals)

    self.handle_page(response, 'locals')

  def handle_remotes(self, response):
    new_remotes = {obj['id']: obj for obj in response['results']}
    self.results.add_remotes(new_remotes)

    self.handle_page(response, 'remotes')

  def handle_matches(self, response):
    def rename(o):
      o['local_id'] = o.pop('from_instance')
      o['remote_id'] = o.pop('to_instance')
      return o

    new_matches = map(rename, response['results'])
    self.results.add_matches(new_matches)

    self.handle_page(response, 'matches')

  def handle_page(self, response, page_type):
    if page_type not in self.seen:
      self.seen.add(page_type)
      self.pbar.setMaximum(self.pbar.maximum() + response['count'])
      self.pbar.setValue(self.pbar.value() + 1)

    self.pbar.setValue(self.pbar.value() + len(response['results']))
    log('match_action').info("result download progress: {} / {} with {}"
                             "".format(self.pbar.value(), self.pbar.maximum(),
                                       self.seen))
    if self.pbar.value() >= self.pbar.maximum():
      self.pbar.accept()

  def accept_results(self):
    # log('match_action').info("Result download completed successfully")
    pass
