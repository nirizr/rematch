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
    self.source = widgets.QRadioExtraLayout(*choices)
    self.source_gbx = QtWidgets.QGroupBox("Match source")
    self.source_gbx.setLayout(self.source)
    self.base_layout.addWidget(self.source_gbx)

    self.target_project = widgets.QItemSelect('projects', allow_none=False)
    self.target_file = widgets.QItemSelect('files', allow_none=False,
                                           exclude=[netnode.bound_file_id])
    choices = [("Entire DB", 'db', None),
               ("Project", 'project', self.target_project),
               ("Another file", 'file', self.target_file)]
    self.target = widgets.QRadioExtraLayout(*choices)
    self.target_gbx = QtWidgets.QGroupBox("Match target")
    self.target_gbx.setLayout(self.target)
    self.base_layout.addWidget(self.target_gbx)

    self.strategy = widgets.QItemRadioGroup('matches/strategies',
                                            'strategy_name', 'strategy_type',
                                            'strategy_description')
    strategy_gbx = QtWidgets.QGroupBox("Match Strategies")
    strategy_gbx.setLayout(self.strategy)
    self.base_layout.addWidget(strategy_gbx)

    self.matchers = widgets.QItemCheckBoxes('matches/matchers', 'matcher_name',
                                            'match_type',
                                            'matcher_description')

    method_gbx = QtWidgets.QGroupBox("Match methods")
    method_gbx.setLayout(self.matchers)
    self.base_layout.addWidget(method_gbx)

    self.bottom_layout("&Start matching")

  def data(self):
    return {'source': self.source.get_result(),
            'source_single': self.source_single.get_result(),
            'source_range': self.source_range.get_result(),
            'target': self.target.get_result(),
            'target_project': self.target_project.currentData(),
            'target_file': self.target_file.currentData(),
            'strategy': self.strategy.get_result(),
            'matchers': self.matchers.get_result()}
