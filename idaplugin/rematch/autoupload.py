import idaapi

from . import actions
from . import dialogs


def main():
  # add file
  add_file_silent = dialogs.silent.SilentDialog([['submit', {}],
                                                 ['response', {}]])
  actions.project.AddFileAction(add_file_silent).activate(None)
  description = "Automatically collected / uploaded by autoupload.py"
  ##############

  # upload data
  # actions.match.MatchAction(MatchSilentUI)


if __name__ == "__main__":
  # action = str(idc.ARGV[1])
  # task_id = int(idc.ARGV[2])
  # owner_id = int(idc.ARGV[3])

  # wait until autoanalysis is done, if needed
  idaapi.autoWait()

  main()

  # and exit the IDA instance
  idaapi.qexit(0)
