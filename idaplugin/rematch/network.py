from idasix import QtCore

import urllib
import urllib2
from cookielib import CookieJar
from json import loads, dumps

import exceptions
from . import config, logger

# building opener
cookiejar = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))

_threadpool = QtCore.QThreadPool()
_threadpool.setMaxThreadCount(config['network']['threadcount'])


class WorkerSignals(QtCore.QObject):
  result_dict = QtCore.pyqtSignal(dict)
  result_list = QtCore.pyqtSignal(list)
  result_str = QtCore.pyqtSignal(str)
  result_exception = QtCore.pyqtSignal(Exception)


class QueryWorker(QtCore.QRunnable):
  def __init__(self, method, url, server=None, token=None, params=None,
               json=False):
    super(QueryWorker, self).__init__()

    self.method = method
    self.url = url
    self.server = server
    self.token = token
    self.params = params
    self.json = json

    self.signals = WorkerSignals()

  def run(self):
    try:
      response = query(self.method, self.url, self.server, self.token,
                       self.params, self.json)
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


def delayed_query(method, url, server=None, token=None, params=None,
                  json=False, callback=None, exception_callback=None):
  query_worker = QueryWorker(method, url, server, token, params, json)
  return delayed_worker(query_worker, callback, exception_callback)


def delayed_worker(query_worker, callback=None, exception_callback=None):
  if callback:
    query_worker.signals.result_dict.connect(callback)
    query_worker.signals.result_list.connect(callback)
    query_worker.signals.result_str.connect(callback)
  if not exception_callback:
    exception_callback = default_exception_callback
  query_worker.signals.result_exception.connect(exception_callback)
  _threadpool.start(query_worker)


def query(method, url, server=None, token=None, params=None, json=False):
  if method not in ("GET", "POST"):
    raise exceptions.QueryException()

  server_url = get_server(server)
  full_url = server_url + url
  headers = get_headers(token, json)

  logger('network').info("[query] {full_url}{headers}{params}"
                         "".format(full_url=full_url, headers=headers,
                                   params=params))
  # issue request
  try:
    if method == "GET":
      if params:
        full_url += "?" + urllib.urlencode(params)
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
    logger('network').info("[response] {}".format(return_obj))
    return return_obj
  except Exception as ex:
    import traceback
    logger.network('network').error(traceback.format_exc())
    rematch_ex = exceptions.factory(ex)
    logger('network').debug(rematch_ex)
    raise rematch_ex


def get_server(server):
  """getting and finalzing server address"""

  try:
   if not server:
    if 'server' not in config and not config['login']['server']:
      raise exceptions.QueryException()
    server = config['login']['server']
   if not (server.startswith("http://") or server.startswith("http://")):
     server = "http://" + server
   if not server.endswith("/"):
     server = server + "/"
  except Exception:
    import traceback
    logger.network('network').error(traceback.format_exc())
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
