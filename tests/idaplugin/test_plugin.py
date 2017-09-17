import time
import sys
import idaplugin
import pytest


class CaptureExceptions(object):
  def __init__(self):
    self.exceptions_caught = []
    self.excepthook = None

  def __enter__(self):
    self.exceptions_caught = []

    def catch(*except_context):
      self.exceptions_caught.append(except_context)

    self.excepthook = sys.excepthook
    sys.excepthook = catch
    return self.exceptions_caught

  def __exit__(self, *args):
    sys.excepthook = self.excepthook
    if self.exceptions_caught:
      raise self.exceptions_caught[0][1]


def test_plugin_creation(idapro_plugin_entry, idapro_app):
  plugin = idapro_plugin_entry()

  plugin.init()

  # TODO: validate return is of PLUGIN_* positive values

  plugin.run()
  idapro_app.processEvents()

  plugin.term()


def test_action_creation(idapro_action_entry, idapro_app):
  action = idapro_action_entry(None)

  if hasattr(idapro_action_entry, 'name'):
    action.register()
    idapro_app.processEvents()

  ctx = None

  if hasattr(idapro_action_entry, 'enabled'):
    action.update(ctx)
    idapro_app.processEvents()

  with pytest.raises(Exception) as exc:
    with CaptureExceptions():
      action.activate(ctx)
      time.sleep(1)
      idapro_app.processEvents()
    assert isinstance(exc, (NotImplementedError,
                            idaplugin.rematch.exceptions.NotFoundException,
                            idaplugin.rematch.exceptions.ConnectionException))


def test_update(idapro_app):
  idaplugin.rematch.update.check_update()
  time.sleep(1)
  idapro_app.processEvents()
