from ..idasix import QtWidgets

from . import gui, widgets
from .. import netnode


class MatchDialog(gui.GuiDialog):
  def __init__(self, **kwargs):
    super(MatchDialog, self).__init__(title="Match", **kwargs)

    self.source_single = widgets.QFunctionSelect()
    self.source_range = widgets.QFunctionRangeSelect()
    lbl = QtWidgets.QLabel("")
    lbl.setDisabled(True)
    lbl.setToolTip("Matching only user functions functionality is not "
                   "currently supported. Plese express your need of this "
                   "functionality at our github.")
    choices = [("Entire IDB", 'idb', None),
               ("User functions", 'user', lbl),
               ("Single function", 'single', self.source_single),
               ("Range", 'range', self.source_range)]
    self.sourceGrp = widgets.QRadioGroup("Match source", *choices)
    self.base_layout.addWidget(self.sourceGrp)

    self.target_project = widgets.QItemSelect('projects', allow_none=False)
    self.target_file = widgets.QItemSelect('files', allow_none=False,
                                           exclude=[netnode.bound_file_id])
    choices = [("Entire DB", 'db', None),
               ("Project", 'project', self.target_project),
               ("Another file", 'file', self.target_file)]
    self.targetGrp = widgets.QRadioGroup("Match target", *choices)
    self.base_layout.addWidget(self.targetGrp)

    self.matchers = widgets.QItemCheckBoxes('matches/matchers', 'matcher_name',
                                            'match_type',
                                            'matcher_description')

    method_gbx = QtWidgets.QGroupBox("Match methods")
    method_gbx.setLayout(self.matchers)
    self.base_layout.addWidget(method_gbx)

    self.bottom_layout("&Start matching")

  def data(self):
    return {'source': self.sourceGrp.get_result(),
            'source_single': self.source_single.get_result(),
            'source_range': self.source_range.get_result(),
            'target': self.targetGrp.get_result(),
            'target_project': self.target_project.currentData(),
            'target_file': self.target_file.currentData(),
            'matchers': self.matchers.get_result()}
