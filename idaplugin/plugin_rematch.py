try:
    # required to run in IDA / python2
    import rematch
except ImportError:
    # required to run in Travis / python3
    from . import rematch


def PLUGIN_ENTRY():  # noqa: N802
  return rematch.plugin.RematchPlugin()
