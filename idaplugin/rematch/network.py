from idasix import QtCore

import urllib
import urllib2
from urlparse import urlparse
from cookielib import CookieJar
from json import loads, dumps

import exceptions
from . import config, log

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
  def __init__(self, method, url, server=None, token=None, params=None,
               json=False, paginate=False):
    super(QueryWorker, self).__init__()

    self.method = method
    self.url = url
    self.server = server
    self.token = token
    self.params = params
    self.json = json
    self.paginate = paginate
    self.running = True
    self.started = False

    if self.paginate and not self.json:
      raise Exception("paginate=True must accompany json=True")

    self.signals = WorkerSignals()

  def start(self, callback=None, exception_callback=None):
    if self.started:
      raise Exception("query worker already started")
    self.started = True

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

  def run(self):
    try:
      while self.running:
        response = query(self.method, self.url, self.server, self.token,
                         self.params, self.json)
        if not self.running:
          break

        if isinstance(response, dict):
          self.signals.result_dict.emit(response)
        elif isinstance(response, list):
          self.signals.result_list.emit(response)
        elif isinstance(response, str):
          self.signals.result_str.emit(response)

        # if request is paginated and was successful, automatically request
        # next page if specified. otherwise, break out of the loop
        if not self.paginate:
          break

        if not isinstance(response, dict):
          raise ValueError("Paginated response object is not a json dict")

        if 'next' not in response or not response['next']:
          break

        url_obj = urlparse(response['next'])
        self.params = url_obj.query
    except Exception as ex:
      self.signals.result_exception.emit(ex)


def default_exception_callback(exception):
  raise exception


def query(method, url, server=None, token=None, params=None, json=False):
  if method not in ("GET", "POST"):
    raise exceptions.QueryException()

  server_url = get_server(server)
  if not server_url:
    raise exceptions.QueryException()

  full_url = server_url + url
  headers = get_headers(token, json)

  log('network').info("[query] %s%s%s", full_url, headers, params)

  # issue request
  try:
    if method == "GET":
      if params:
        if isinstance(params, dict):
          params = urllib.urlencode(params)
        full_url += "?" + params
      request = urllib2.Request(full_url, headers=headers)
    elif method == "POST":
      if not params:
        params = ""
      elif json:
        params = dumps(params)
      request = urllib2.Request(full_url, data=params, headers=headers)

    response = opener.open(request)

    # return response
    return_obj = loads(response.read()) if json else response.read()
    log('network').info("[response] %s", return_obj)
    return return_obj
  except Exception as ex:
    rematch_ex = exceptions.factory(ex)
    log('network').exception(rematch_ex)
    raise rematch_ex


def get_server(server):
  """getting and finalzing server address"""

  try:
    if not server and 'login' in config and config['login']['server']:
      server = config['login']['server']
    if not (server.startswith("http://") or server.startswith("http://")):
      server = "http://" + server
    if not server.endswith("/"):
      server = server + "/"
  except Exception:
    log('network').exception("Failed generating server address")
  return server


def get_headers(token, json):
  """Setting up headers"""

  headers = {}
  if json:
    headers['Accept'] = 'application/json, text/html, */*'
    headers['Content-Type'] = 'application/json'
  if token is None and 'token' in config['login']:
    token = config['login']['token']
  if token:
    headers['Authorization'] = 'Token {}'.format(token)

  return headers
