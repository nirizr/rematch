import pytest

from idaplugin.rematch.dialogs.base import BaseDialog
from idaplugin.rematch.dialogs.widgets import QItem
from idaplugin.rematch.exceptions import NotFoundException


def recurse_subclasses(classes):
  if not classes:
    return set()

  subclasses = set()
  for cls in classes:
    subclasses |= set(cls.__subclasses__())

  return classes | recurse_subclasses(subclasses)


dialogs = recurse_subclasses({BaseDialog})
dialogs = sorted(dialogs, key=lambda d: d.__class__.__name__)


known_failing_dialogs = {'MatchDialog': (NotFoundException, AttributeError),
                         'AddFileDialog': NotFoundException,
                         'SettingsDialog': NotFoundException,
                         'MatchResultDialog': TypeError}


@pytest.mark.parametrize("dialog_entry", dialogs)
def test_dialog(dialog_entry, idapro_app):
  try:
    dialog = dialog_entry()

    if hasattr(dialog, 'show'):
      dialog.show()
      idapro_app.processEvents()

    if hasattr(dialog, 'findChildren'):
      query_items = dialog.findChildren(QItem)
      queries = [i.query for i in query_items]

      dialog.show()

      while any(q.running or not q.started for q in queries):
        idapro_app.processEvents()
  except Exception as ex:
    if (dialog_entry.__name__ in known_failing_dialogs and
        isinstance(ex, known_failing_dialogs[dialog_entry.__name__])):
      import traceback
      pytest.xfail("Dialog {} which was expected to fail failed with "
                   "exception {}. {}".format(dialog_entry.__name__, str(ex),
                                             traceback.format_exc()))
    raise
