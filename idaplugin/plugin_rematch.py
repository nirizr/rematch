try:
    # required to run in IDA / python2
    import rematch
except ImportError as ex:
    # let all other ImportErrors pass through
    if not ex.args[0] == "No module named 'rematch'":
        raise
    # required to run in Travis / python3
    from . import rematch


def PLUGIN_ENTRY():  # noqa: N802
  return rematch.plugin.RematchPlugin()
