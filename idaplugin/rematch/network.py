import urllib
import urllib2
from cookielib import CookieJar
from json import loads, dumps

import exceptions
from . import config, logger

# building opener
cookiejar = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))


def query(method, url, server=None, token=None, params={}, json=False):
  if method not in ("GET", "POST"):
    raise exceptions.QueryException()

  if method == "GET":
    params = "?" + urllib.urlencode(params)
  elif method == "POST" and json:
    params = dumps(params)

  # getting and finalzing server address
  if not server:
    if 'server' not in config or not config['server']:
      raise exceptions.QueryException()
    server = config['server']
  if not (server.startswith("http://") or server.startswith("http://")):
    server = "http://" + server
  if not server.endswith("/"):
    server = server + "/"

  # Setting up headers
  headers = {}
  headers['Accept'] = 'application/json, text/html, */*'
  headers['Content-Type'] = 'application/json'
  if token is None and 'token' in config and config['token']:
    token = config['token']
  if token:
    headers['Authorization'] = 'Token {}'.format(token)

  full_url = server + url

  logger('network').info("[query] params {full_url}{headers}{params}"
                         "".format(full_url=full_url, headers=headers,
                                   params=params))

  # issue request
  try:
    if method == "GET":
      request = urllib2.Request(full_url + params, headers=headers)
    elif method == "POST":
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
