class RematchException(Exception):
  message = ""

  def __str__(self):
    return "<{}: {}>".format(self.__class__, self.message)


class UnsavedIdb(RematchException):
  message = ("You mast save the IDB before uploading it to the database, "
             "please save and try again")


class QueryException(RematchException):
  message = ("Local error has occured! please report a reproducable bug if "
             "this issue persists")


class ConnectionException(QueryException):
  message = ("Can't connect to the server. Either your network connection is "
             "broken or the server is momentarily unavailable.")


class ServerException(QueryException):
  message = ("opps! we had a server error error. If this problem persists "
             "please report this issue.")


class AuthenticationException(RematchException):
  message = ("Failed authentication check on server. Please verify your "
             "credentials and try again")


class NotFoundException(QueryException):
  message = ("Asset not found. This could be either a plugin error or a "
             "server error.")
