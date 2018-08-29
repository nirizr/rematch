import time
import idaplugin


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

  try:
    action.activate(ctx)
    time.sleep(1)
    idapro_app.processEvents()
  except (NotImplementedError,
          idaplugin.rematch.exceptions.NotFoundException,
          idaplugin.rematch.exceptions.ConnectionException):
    pass


def test_update(idapro_app):
  update_checker = idaplugin.rematch.update.UpdateChecker()
  update_checker.check_update()
  while update_checker.status == "pending":
    idapro_app.processEvents()
