import idaapi

from . import actions


def silent_ui(calls):
  def silent(reject_handler=None, submit_handler=None, response_handler=None,
             exception_handler=None):
    for handler, kwargs in calls:
      if handler == 'reject':
        reject_handler(**kwargs)
      elif handler == 'submit':
        submit_handler(**kwargs)
      elif handler == 'response':
        response_handler(**kwargs)
      elif handler == 'exception':
        exception_handler(**kwargs)

  return silent


class AddFileDialog(dialogs.silent.SilentDialog):
  calls = [['submit', {}],
           ['response', {}]]


def main():
  # add file
  add_file_silent = silent_ui([['submit', {}],
                               ['response', {}]])
  actions.project.AddFileAction(add_file_silent).activate()
  #description = "Automatically collected / uploaded by autoupload.py"
  ##############

  # upload data
  #actions.match.MatchAction(MatchSilentUI)


if __name__ == "__main__":
  # action = str(idc.ARGV[1])
  # task_id = int(idc.ARGV[2])
  # owner_id = int(idc.ARGV[3])

  # wait until autoanalysis is done, if needed
  idaapi.autoWait()

  main()

  # and exit the IDA instance
  idaapi.qexit(0)
