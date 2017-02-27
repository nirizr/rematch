import os

from ..idasix import QtWidgets

from . import base
from .. import utils


class ResultScriptDialog(base.BaseDialog):
  def __init__(self, *args, **kwargs):
    super(ResultScriptDialog, self).__init__("Result script", *args, **kwargs)

    self.scripts_path = utils.getPluginPath('scripts')

    self.script_txt = QtWidgets.QTextEdit()
    self.status_lbl = QtWidgets.QLabel()
    self.status_lbl.setStyleSheet("color: red;")
    self.cb = QtWidgets.QComboBox()

    if not os.path.exists(self.scripts_path):
      os.makedirs(self.scripts_path)

    for script_name in os.listdir(self.scripts_path):
      if script_name.endswith(".pyf"):
        self.cb.addItem(script_name)

    if self.cb.count() > 0:
      default_script = os.path.join(self.scripts_path, self.cb.itemText(0))
      with open(default_script, "r") as fh:
        data = fh.read()
        self.script_txt.setText(data)

    self.new_btn = QtWidgets.QPushButton("&New")
    self.save_btn = QtWidgets.QPushButton("&Save")
    self.apply_btn = QtWidgets.QPushButton("&Apply")
    self.cancel_btn = QtWidgets.QPushButton("&Cancel")

    size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                        QtWidgets.QSizePolicy.Fixed)
    self.new_btn.setSizePolicy(size_policy)
    self.save_btn.setSizePolicy(size_policy)
    self.apply_btn.setSizePolicy(size_policy)
    self.cancel_btn.setSizePolicy(size_policy)

    self.button_layout = QtWidgets.QGridLayout()
    self.button_layout.addWidget(self.new_btn, 0, 0)
    self.button_layout.addWidget(self.save_btn, 0, 1)
    self.button_layout.addWidget(self.apply_btn, 1, 0)
    self.button_layout.addWidget(self.cancel_btn, 1, 1)

    self.apply_btn.clicked.connect(self.validate)
    self.cancel_btn.clicked.connect(self.reject)
    self.save_btn.clicked.connect(self.save_file)
    self.new_btn.clicked.connect(self.new_script)

    self.cb.resize(200, 200)

    help_tooltip = ["While executing the script code, the following context "
                    "variables are available:",
                    "<b>Filter</b>: defaults to False. determines wether "
                    "this item should be filtered out (you should change "
                    "this)",
                    "<b>Errors</b>: defaults to 'stop'. when a runtime "
                    "error occures in script code this will help determine "
                    "how to continue.",
                    "There are several valid values:",
                    " - '<b>stop</b>': handle runtime errors as ",
                    "non-continual. stop using filters immidiately.",
                    " - '<b>filter</b>': filter this function using whatever "
                    "value was in Filter at the time of the error",
                    " - '<b>hide</b>': hide all functions in which a "
                    "filtering error occured, after displaying a warning.",
                    " - '<b>show</b>': show all functions in which a "
                    "filtering error occured, after displaying a warning.",
                    "",
                    "When filtering a match function(a leaf) both the local "
                    "and match variables exist.",
                    "When filtering a local function(a tree root) only the "
                    "local variable exist, and remote equals to None.",
                    "The local variable describes the local function (tree "
                    "root), and the match variable describes the function "
                    "matched to the local one(the local root's leaf).",
                    "both the local and match variables, if exist, are "
                    "dictionaries containing these keys:",
                    "<b>'ea'</b>: effective address of function",
                    "<b>'name'</b>: name of function (or a string of ea in "
                    "hexadecimal if no name defined for match functions)",
                    "<b>'docscore'</b>: a float between 0 and 1.0 "
                    "representing the documentation score of function",
                    "<b>'score'</b>: (INTERNAL) a float between 0 and 1.0 "
                    "representing the match score of this function and the "
                    "core element",
                    "<b>'key'</b>: (INTERNAL) the match type.",
                    "<b>'documentation'</b>: (INTERNAL) available "
                    "documentation for each line of code",
                    "<b>'local'</b> : True if this function originated from "
                    "the local binary (for when a local function matched "
                    "another local function).",
                    "",
                    "Note: variables marked as INTERNAL are likely to change "
                    "in format, content and values without prior notice. your "
                    "code may break.",
                    "user discretion is advised."]
    help_tooltip = "\n".join(help_tooltip)

    self.help_lbl = QtWidgets.QLabel("Insert native python code to filter "
                                     "matches:\n(Hover for more information)")
    self.help_lbl.setToolTip(help_tooltip)

    self.combo_layout = QtWidgets.QHBoxLayout()
    self.combo_layout.addWidget(QtWidgets.QLabel("Script - "))
    self.combo_layout.addWidget(self.cb)

    self.base_layout.addWidget(self.help_lbl)
    self.base_layout.addLayout(self.combo_layout)
    self.base_layout.addWidget(self.script_txt)
    self.base_layout.addWidget(self.status_lbl)
    self.base_layout.addLayout(self.button_layout)

    self.cb.currentTextChanged.connect(self.combobox_change)

  def save_file(self):
    current_file = self.cb.currentText()
    fpath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Data File",
                                                     self.scripts_path,
                                                     "Python files (*.pyf)")
    if not fpath:
      return

    with open(fpath, 'w') as fh:
      fh.write(self.script_txt.toPlainText())

    self.cb.clear()
    for file in os.listdir(self.scripts_path):
      if file.endswith(".pyf"):
        self.cb.addItem(file)
    self.cb.setCurrentText(current_file)

  def new_script(self):
    if not self.cb.itemText(0) == "New":
      self.cb.insertItem(0, "New")
      self.cb.setCurrentIndex(0)

  def combobox_change(self, new_value):
    fpath = os.path.join(self.scripts_path, new_value)
    if os.path.isfile(fpath):
      with open(fpath, "r") as myfile:
        data = myfile.read()
    else:
      data = ""
    self.script_txt.setText(data)

  def get_code(self):
    return self.script_txt.toPlainText()

  def validate(self):
    try:
      compile(self.get_code(), '<input>', 'exec')
    except Exception as ex:
      self.status_lbl.setText(str(ex))
    else:
      self.accept()
