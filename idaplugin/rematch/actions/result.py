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

    self.compiled_filter = None

    self.delayed_queries = []

    self.task_id = None
    self.local_count, self.local_count, self.local_count = 0, 0, 0
    if task_data:
      self.set_task_data(task_data)

    self.timer = QtCore.QTimer()

  def set_task_data(self, task_data):
    self.task_id = task_data['id']
    self.local_count = task_data['local_count']
    self.remote_count = task_data['remote_count']
    self.match_count = task_data['match_count']
    log('result').info("Task counts: %s, %s, %s", self.local_count,
                       self.remote_count, self.match_count)

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
    params = {'from_matches__task': self.task_id}
    q = network.QueryWorker("GET", "collab/instances/", paginated=True,
                            json=True, params=params)
    self.delayed_queries.append(q)
    q.start(self.handle_locals)

    params = {'to_matches__task': self.task_id,
              'annotation_count': True}
    q = network.QueryWorker("GET", "collab/instances/", paginated=True,
                            json=True, params=params)
    self.delayed_queries.append(q)
    q.start(self.handle_remotes)

    q = network.QueryWorker("GET", "collab/matches/", paginated=True,
                            json=True, params={'task': self.task_id})
    self.delayed_queries.append(q)
    q.start(self.handle_matches)

  def handle_locals(self, response):
    for obj in response['results']:
      # if local item was already created for a match result, update it with
      # actual local item information while keeping any matches, otherwise
      # create an empty matches list and assign object
      if obj['id'] in self.locals:
        self.locals[obj['id']].update(obj)
      else:
        self.locals[obj['id']] = obj
        self.locals[obj['id']]['matches'] = []

    log('result').info("locals new results %s", len(response['results']))
    self.handle_page(len(response['results']))

  def handle_remotes(self, response):
    # this is pretty simple, just hold a mapping from ids to objects
    for obj in response['results']:
      self.remotes[obj['id']] = obj

    log('result').info("remotes new results %s", len(response['results']))
    self.handle_page(len(response['results']))

  def handle_matches(self, response):
    for match in response['results']:
      local_id = match['from_instance']
      # TODO: local_id may be removed instead of renamed to save some space
      # Some other bits of data may also be removed
      match['local_id'] = match.pop('from_instance')
      match['remote_id'] = match.pop('to_instance')

      # create an empty local item if matched local item was not processed yet
      if local_id not in self.locals:
        self.locals[local_id] = {}
      if 'matches' not in self.locals[local_id]:
        self.locals[local_id]['matches'] = []

      # append match to locals
      self.locals[local_id]['matches'].append(match)

    log('result').info("match new results %s", len(response['results']))
    self.handle_page(len(response['results']))

  def handle_page(self, results_count):
    self.ui.progress.setValue(self.ui.progress.value() + results_count)
    log('result').info("result download progress: {} / {}"
                       "".format(self.ui.progress.value(),
                                 self.ui.progress.maximum()))
    if self.ui.progress.value() >= self.ui.progress.maximum():
      self.download_complete()

  def download_complete(self):
    # TODO: perform the following while data comes in instead of after it
    # arrived. Also, schedule execution using a timer to not hang
    self.populate_tree()
    self.ui.set_checks()

    log('result').info("Result download completed successfully")
    self.ui.set_status("Result download complete")

  def build_context(self, local, match=None, remote=None):
    log('result').info("building context %s %s %s", local, match, remote)
    context = {'Filter': False}

    local = {'offset': local['offset'], 'name': local['name'],
             'local': True}
    context['local'] = local

    if remote:
      remote = {'offset': remote['offset'], 'name': remote['name'],
                'score': match["score"], 'key': match["type"],
                'local': remote['id'] in self.locals.keys()}
    context['remote'] = remote

    return context

  def should_filter(self, context):
    if not self.compiled_filter:
      return False

    try:
      exec(self.compiled_filter, context)
    except Exception as ex:
      errors = context.get('Errors', 'stop')
      if errors == 'stop':
        self.compiled_filter = None
        log('result').warning("Filter function encountered a runtime error: "
                              "%s.\nDisabling filters.", ex)
      elif errors == 'filter':
        pass
      elif errors == 'hide':
        return True
      elif 'errors' == 'show':
        return False
    return 'Filter' in context and context['Filter']

  def populate_tree(self):
    for local_obj in self.locals.values():
      context = self.build_context(local_obj)
      if self.should_filter(context):
        continue

      local_item = self.ui.populate_item(None, local_obj)
      for match_obj in local_obj['matches']:
        remote_obj = self.remotes[match_obj['remote_id']]

        context = self.build_context(local_obj, match_obj, remote_obj)
        if self.should_filter(context):
          continue

        self.ui.populate_item(local_item, remote_obj, match_obj)

  def get_obj(self, obj_id):
    if obj_id in self.locals:
      return self.locals[obj_id]
    else:
      return self.remotes[obj_id]
