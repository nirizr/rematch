from ..idasix import QtCore

from ..dialogs.result import ResultDialog

from .. import network, log
from . import base


class ResultAction(base.BoundFileAction):
  name = "&Result"
  dialog = ResultDialog

  def __init__(self, task_data=None, *args, **kwargs):
    super(ResultAction, self).__init__(*args, **kwargs)
    self.instances = None
    self.file_version_id = None
    self.locals = {}
    self.remotes = {}
    self.matches = []

    self.task_id = None
    self.local_count, self.local_count, self.local_count = 0, 0, 0
    if task_data:
      self.set_task_data(task_data)

    self.delayed_queries = []

    self.timer = QtCore.QTimer()

  def set_task_data(self, task_data):
    self.task_id = task_data['id']
    self.local_count = task_data['local_count']
    self.remote_count = task_data['remote_count']
    self.match_count = task_data['match_count']

  def activate(self, ctx=None):
    super(ResultAction, self).activate(ctx)

    # if we got a task id, lets start pulling results. Otherwise, we'll wait
    # for submit_handler to be called from ResultDialog
    if self.task_id:
      self.start_results()

  def start_results(self):
    self.ui.set_status("Receiving match results...")
    self.ui.progress.setRange(0, (self.local_count + self.remote_count +
                                  self.match_count))
    self.ui.progress.setValue(0)

    log('result').info("Result download started")
    locals_url = "collab/instances/?from_matches__task={}".format(self.task_id)
    q = network.QueryWorker("GET", locals_url, json=True, paginated=True)
    q.start(self.handle_locals)
    self.delayed_queries.append(q)

    remotes_url = ("collab/instances/?to_matches__task={}"
                   "&annotation_count=true".format(self.task_id))
    q = network.QueryWorker("GET", remotes_url, json=True, paginated=True)
    q.start(self.handle_remotes)
    self.delayed_queries.append(q)

    matches_url = "collab/matches/?task={}".format(self.task_id)
    q = network.QueryWorker("GET", matches_url, json=True, paginated=True)
    q.start(self.handle_matches)
    self.delayed_queries.append(q)

  def handle_locals(self, response):
    for obj in response['results']:
      # if local item was already created for a match result, update it with
      # actual local item information while keeping any matches, otherwise
      # create an empty matches list and assign object
      if obj['id'] in self.locals:
        self.locals[obj['id']].update(obj)
      else:
        self.locals[obj['id']] = obj
        self.locals['matches'] = []

    self.handle_page(response)

  def handle_remotes(self, response):
    # this is pretty simple, just hold a mapping from ids to objects
    for obj in response['results']:
      self.remotes[obj['id']] = obj

    self.handle_page(response)

  def handle_matches(self, response):
    for match in response['results']:
      from_instance = match['from_instance']
      # TODO: local_id may be removed instead of renamed to save some space
      # Some other bits of data may also be removed
      match['local_id'] = match.pop('from_instance')
      match['remote_id'] = match.pop('to_instance')

      # create an empty local item if matched local item was not processed yet
      if from_instance not in self.locals:
        self.locals[from_instance] = {'matches': []}

      # append match to locals
      self.locals[from_instance]['matches'].append(match)

    self.handle_page(response)

  def handle_page(self, response):
    self.ui.progress.setValue(self.ui.progress.value() +
                              len(response['results']))
    log('result').info("result download progress: {} / {}"
                       "".format(self.ui.progress.value(),
                                 self.ui.progress.maximum()))
    if self.ui.progress.value() >= self.ui.progress.maximum():
      self.download_complete()

  def download_complete(self):
    # TODO: perform the following while data comes in instead of after it
    # arrived. Also, schedule execution using a timer to not hang
    self.populate_tree()
    self.set_checks()

    log('result').info("Result download completed successfully")
    self.ui.set_status("Result download complete")
