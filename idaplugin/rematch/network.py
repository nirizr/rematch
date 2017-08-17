from idasix import QtCore

import urllib
import urllib2
from urlparse import urlparse
from cookielib import CookieJar
from json import loads, dumps

import exceptions
from . import config, log, utils

# building opener
cookiejar = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))

_threadpool = QtCore.QThreadPool()
_threadpool.setMaxThreadCount(config['network']['threadcount'])


class WorkerSignals(QtCore.QObject):
  result_dict = QtCore.Signal(dict)
  result_list = QtCore.Signal(list)
  result_str = QtCore.Signal(str)
  result_exception = QtCore.Signal(Exception)


class QueryWorker(QtCore.QRunnable):
  SPLIT = 900

  def __init__(self, method, url, server=None, token=None, params=None,
               json=False, pageable=False, splittable=None):
    super(QueryWorker, self).__init__()

    if pageable and splittable:
      raise ValueError("QueryWorker can only be one of splittable and"
                       "pageable, not both.")

    if (pageable or splittable) and not isinstance(params, dict):
      raise ValueError("QueryWorker can only be pageable or splittable when"
                       "params is a dictionary.")

    if pageable and not json:
      raise Exception("pageable=True must accompany json=True")

    self.method = method
    self.url = url
    self.server = server
    self.token = token
    self.params = params
    self.json = json
    self.pageable = pageable
    self.splittable = splittable
    if self.splittable:
      self.splittable_values = self.params[self.splittable]
    else:
        self.splittable_values = None
    self.running = False
    self.started = False

    self.signals = WorkerSignals()

  def start(self, callback=None, exception_callback=None, requeue=None):
    if self.started:
      raise Exception("query worker already started")

    if requeue and not callback:
      raise Exception("cannot requeue without a callable")

    if requeue not in (None, 'read', 'write'):
      raise Exception("requeue possible values are: None, 'read' or 'write', "
                      "got: {}".format(requeue))

    self.running = True
    self.started = True

    if requeue:
      requeue = requeue == 'write'
      callback = utils.ida_kernel_queue(write=requeue)(callback)

    if callback:
      self.signals.result_dict.connect(callback)
      self.signals.result_list.connect(callback)
      self.signals.result_str.connect(callback)
    if not exception_callback:
      exception_callback = default_exception_callback
    self.signals.result_exception.connect(exception_callback)
    _threadpool.start(self)

  def cancel(self):
    self.running = False

  def run_query(self):
    while self.running:
      # if we're running a splittable query, only send SPLIT parameters for the
      # splittable variable
      if self.splittable:
        self.params[self.splittable] = self.splittable_values[:self.SPLIT]
        self.splittable_values = self.splittable_values[self.SPLIT:]

      response = query(self.method, self.url, self.server, self.token,
                       self.params, self.json)

      yield response

      # if request is pageabled and was successful, automatically request
      # next page if specified. otherwise, break out of the loop
      if self.pageable:
        if not isinstance(response, dict):
          raise ValueError("pageabled response object is not a json dict")

        if 'next' in response and response['next']:
          url_obj = urlparse(response['next'])
          self.params = url_obj.query
          continue
      elif self.splittable and self.splittable_values:
        continue

      # by default, only perform this loop once, unless there was a reason to
      # continue
      break

  def run(self):
    try:
      for response in self.run_query():
        # make sure QueryWorker wasn't cancelled while query was blocking
        if not self.running:
          break

        if isinstance(response, dict):
          self.signals.result_dict.emit(response)
        elif isinstance(response, list):
          self.signals.result_list.emit(response)
        elif isinstance(response, str):
          self.signals.result_str.emit(response)
    except Exception as ex:
      self.signals.result_exception.emit(ex)


def default_exception_callback(exception):
  raise exception


def build_params(method, params):
  """Convert params format based on request paramters."""
  if not params:
    return ""

  if method == "POST" and isinstance(params, (list, dict)):
    return dumps(params)
  elif method == "GET" and isinstance(params, dict):
    return urllib.urlencode(params, doseq=True)

  return params


def query(method, url, server=None, token=None, params=None, json=False):
  if method not in ("GET", "POST"):
    raise exceptions.QueryException()

  server_url = get_server(server)
  if not server_url:
    raise exceptions.QueryException()

  full_url = server_url + url
  headers = get_headers(token, json)

  log('network').info("[query] %s %s%s%s", method, full_url, headers, params)

  # issue request
  try:
    params = build_params(method, params)

    if method == "GET":
      request = urllib2.Request(full_url + "?" + params, headers=headers)
    elif method == "POST":
      request = urllib2.Request(full_url, data=params, headers=headers)

    response = opener.open(request)

    # return response
    response_obj = response.read()
    log('network').info("[response] %s", response_obj)
    if json:
      response_obj = loads(response_obj)
    return response_obj
  except Exception as ex:
    exceptions.factory(ex)


def get_server(server):
  """getting and finalzing server address."""

  try:
    if not server and 'login' in config and config['login']['server']:
      server = config['login']['server']
    if not (server.startswith("http://") or server.startswith("https://")):
      server = "http://" + server
    if not server.endswith("/"):
      server = server + "/"
  except Exception:
    log('network').exception("Failed generating server address")
  return server


def get_headers(token, json):
  """Setting up headers."""

  headers = {}
  if json:
    headers['Accept'] = 'application/json, text/html, */*'
    headers['Content-Type'] = 'application/json'
  if token is None and 'token' in config['login']:
    token = config['login']['token']
  if token:
    headers['Authorization'] = 'Token {}'.format(token)

  return headers
