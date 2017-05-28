import idaapi

try:
  import rematch.actions as actions
  import rematch.dialogs as dialogs
except ImportError:
  from . import actions
  from . import dialogs


def main():
  # add file
  description = "Automatically collected / uploaded by autoupload.py"
  calls = [('submit', {'project': -1, 'name': "filename", 'md5hash': "hash",
                       'description': description, 'shareidb': True})]
  add_file_silent = dialogs.silent.SilentDialog(calls)
  actions.project.AddFileAction(add_file_silent).activate(None)

  ##############
  # skipped: add a project for file
  calls = [('submit', {'name': "proj_name", 'description': description,
                       'private': False, 'bind_current': True})]
  add_file_silent = dialogs.silent.SilentDialog(calls)

  # upload data and start matching
  calls = [('submit', {'source': 'idb', 'source_single': None,
                       'source_range': None, 'target': 'db',
                       'target_project': None, 'target_file': None,
                       'matchers': None})]
  match_silent = dialogs.silent.SilentDialog(calls)
  actions.match.MatchAction(match_silent).activate(None)


if __name__ == "__main__":
  # action = str(idc.ARGV[1])
  # task_id = int(idc.ARGV[2])
  # owner_id = int(idc.ARGV[3])

  # wait until autoanalysis is done, if needed
  idaapi.autoWait()

  main()

  # and exit the IDA instance
  idaapi.qexit(0)
