import urllib
import urllib2
from cookielib import CookieJar
from json import loads, dumps

import exceptions
from . import config, logger

# building opener
cookiejar = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))


def query(method, url, server=None, token=None, params=None, json=False):
  if method not in ("GET", "POST"):
    raise exceptions.QueryException()

  full_url = get_server(server) + url
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
  except urllib2.HTTPError as ex:
    logger('network').debug(ex)
    logger('network').debug(ex.read())
    logger('network').debug(ex.__dict__)
    if ex.code in (500,):
      raise exceptions.ServerException()
    if ex.code in (401,):
      raise exceptions.AuthenticationException()
    if ex.code in (404,):
      raise exceptions.NotFoundException()
    raise
  except urllib2.URLError as ex:
    raise exceptions.ConnectionException()


def get_server(server):
  """getting and finalzing server address"""

  if not server:
    if 'server' not in config or not config['server']:
      raise exceptions.QueryException()
    server = config['server']
  if not (server.startswith("http://") or server.startswith("http://")):
    server = "http://" + server
  if not server.endswith("/"):
    server = server + "/"

  return server


def get_headers(token, json):
  """Setting up headers"""

  headers = {}
  if json:
    headers['Accept'] = 'application/json, text/html, */*'
    headers['Content-Type'] = 'application/json'
  if token is None and 'token' in config and config['token']:
    token = config['token']
  if token:
    headers['Authorization'] = 'Token {}'.format(token)

  return headers
