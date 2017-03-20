from ..idasix import QtWidgets

from . import base
from .. import netnode


class MatchDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(MatchDialog, self).__init__(title="Match", **kwargs)

    self.source_single = base.QFunctionSelect()
    self.source_range = base.QFunctionRangeSelect()
    lbl = QtWidgets.QLabel("")
    lbl.setDisabled(True)
    lbl.setToolTip("Matching only user functions functionality is not "
                   "currently supported. Plese express your need of this "
                   "functionality at our github.")
    choices = [("Entire IDB", 'idb', None),
               ("User functions", 'user', lbl),
               ("Single function", 'single', self.source_single),
               ("Range", 'range', self.source_range)]
    self.sourceGrp = base.QRadioGroup("Match source", *choices)
    self.base_layout.addWidget(self.sourceGrp)

    self.target_project = base.QItemSelect('projects', allow_none=False)
    self.target_file = base.QItemSelect('files', allow_none=False,
                                        exclude=[netnode.bound_file_id])
    choices = [("Entire DB", 'db', None),
               ("Project", 'project', self.target_project),
               ("Another file", 'file', self.target_file)]
    self.targetGrp = base.QRadioGroup("Match target", *choices)
    self.base_layout.addWidget(self.targetGrp)

    self.matchers = base.QItemCheckBoxes(item='matches/matchers',
                                         name_field='matcher_name',
                                         id_field='match_type')

    method_gbx = QtWidgets.QGroupBox("Match methods")
    method_gbx.setLayout(self.matchers)
    self.base_layout.addWidget(method_gbx)

    self.bottom_layout("&Start matching")

  def data(self):
    return {'source': self.sourceGrp.get_result(),
            'source_single': self.source_single.func.startEA
                               if self.source_single.func else None,
            'source_range': [self.source_range.start.func.startEA
                               if self.source_range.start.func else None,
                             self.source_range.end.func.endEA
                               if self.source_range.end.func else None],
            'target': self.targetGrp.get_result(),
            'target_project': self.target_project.currentData(),
            'target_file': self.target_file.currentData(),
            'matchers': self.matchers.get_result()}
