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

    self.identity = QtWidgets.QCheckBox("Identify matches")
    self.fuzzy = QtWidgets.QCheckBox("Fuzzy matches")
    self.graph = QtWidgets.QCheckBox("Graph matches")
    self.identity.setChecked(True)
    self.fuzzy.setChecked(True)
    self.graph.setChecked(True)
    method_lyt = QtWidgets.QVBoxLayout()
    method_lyt.addWidget(self.identity)
    method_lyt.addWidget(self.fuzzy)
    method_lyt.addWidget(self.graph)

    method_gbx = QtWidgets.QGroupBox("Match methods")
    method_gbx.setDisabled(True)
    method_gbx.setToolTip("Match method control functionality is not "
                          "currently supported. Plese express your need of "
                          "this functionality at our github.")
    method_gbx.setLayout(method_lyt)
    self.base_layout.addWidget(method_gbx)

    self.bottom_layout("&Start matching")

  def data(self):
    methods = []
    if self.identity.isChecked():
      methods.append('identity')
    if self.fuzzy.isChecked():
      methods.append('fuzzy')
    if self.graph.isChecked():
      methods.append('graph')

    return {'source': self.sourceGrp.get_result(),
            'source_single': self.source_single.func.startEA,
            'source_range': [self.source_range.start.func.startEA,
                             self.source_range.end.func.endEA],
            'target': self.targetGrp.get_result(),
            'target_project': self.target_project.currentData(),
            'target_file': self.target_file.currentData(),
            'methods': methods}
