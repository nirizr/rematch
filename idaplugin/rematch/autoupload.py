import idc
import idaapi

from . import network
from . import actions


class AddFileSilentUI(actions.base.Action):
  pass


class MatchSilentUI(actions.base.Action):
  pass


def main():
  # add file
  actions.project.AddFileAction(AddFileSilentUI)
  description = "Automatically collected / uploaded by autoupload.py"
  ##############

  # upload data
  actions.match.MatchAction(MatchSilentUI)


if __name__ == "__main__":
  # action = str(idc.ARGV[1])
  # task_id = int(idc.ARGV[2])
  # owner_id = int(idc.ARGV[3])

  # wait until autoanalysis is done, if needed
  idaapi.autoWait()

  main()

  # and exit the IDA instance
  idaapi.qexit(0)
