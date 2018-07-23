from .idasix import QtCore

import urllib
try:
  import urllib2 as request
  from urlparse import urlparse
  from cookielib import CookieJar
except ImportError:
  from urllib import request
  from urllib.parse import urlparse
  from http.cookiejar import CookieJar

from json import loads, dumps

from . import config, log, utils, exceptions

# building opener
cookiejar = CookieJar()
opener = request.build_opener(request.HTTPCookieProcessor(cookiejar))

_threadpool = QtCore.QThreadPool()
_threadpool.setMaxThreadCount(config['network']['threadcount'])


class WorkerSignals(QtCore.QObject):
  result = QtCore.Signal(object)
  error = QtCore.Signal(Exception, str)


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

  def start(self, callback=None, exception_callback=None, write=False,
            wait=False):
    if self.started:
      raise Exception("query worker already started")

    self.running = True
    self.started = True

    if callback:
      def callback_wrap(result):
        try:
          callback(result)
        except Exception:
          import traceback
          traceback.print_exc()

      ida_kernel_enqueue = utils.IdaKernelQueue(write=write, wait=wait)
      callback_wrap = ida_kernel_enqueue(callback_wrap)

      self.signals.result.connect(callback_wrap)

    if not exception_callback:
      exception_callback = default_exception_callback
    self.signals.error.connect(exception_callback)

    _threadpool.start(self)

  def cancel(self):
    if not self.running:
      return

    log('network').info("async task cancelled: %s", repr(self))
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
      self.running = False

  def run(self):
    try:
      for response in self.run_query():
        # make sure QueryWorker wasn't cancelled while query was blocking
        if not self.running:
          break

        self.signals.result.emit(response)
    except Exception as ex:
      self.running = False
      import traceback
      self.signals.error.emit(ex, traceback.format_exc())

  def __del__(self):
    if self.running:
      log('network').warn('Worker deleted while running: %s', self.url)


def default_exception_callback(exception, traceback):
  del exception
  log('main').warn("callback exception: %s", traceback)


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
      req = request.Request(full_url + "?" + params, headers=headers)
    elif method == "POST":
      req = request.Request(full_url, data=params, headers=headers)

    response = opener.open(req)

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
