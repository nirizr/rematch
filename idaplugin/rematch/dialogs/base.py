from ..idasix import QtWidgets, QtCore

import idaapi
import idc

from .. import network


class BaseDialog(QtWidgets.QDialog):
  def __init__(self, title="", reject_handler=None, submit_handler=None,
               response_handler=None, exception_handler=None, **kwargs):
    super(BaseDialog, self).__init__(**kwargs)
    self.setModal(True)
    self.setWindowTitle(title)
    self.reject_handler = reject_handler
    self.submit_handler = submit_handler
    self.response_handler = response_handler
    self.exception_handler = exception_handler
    self.response = None
    self.statusLbl = None

    self.base_layout = QtWidgets.QVBoxLayout()
    self.setLayout(self.base_layout)

  def bottom_layout(self, ok_text="&Ok", cencel_text="&Cancel"):
    self.statusLbl = QtWidgets.QLabel()
    self.base_layout.addWidget(self.statusLbl)

    ok_btn = QtWidgets.QPushButton(ok_text)
    ok_btn.setDefault(True)
    cancel_btn = QtWidgets.QPushButton(cencel_text)
    size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                        QtWidgets.QSizePolicy.Fixed)
    ok_btn.setSizePolicy(size_policy)
    cancel_btn.setSizePolicy(size_policy)
    button_lyt = QtWidgets.QHBoxLayout()
    button_lyt.addWidget(ok_btn)
    button_lyt.addWidget(cancel_btn)
    self.base_layout.addLayout(button_lyt)

    ok_btn.clicked.connect(self.submit_base)
    cancel_btn.clicked.connect(self.reject_base)

  def submit_base(self):
    # if no submit_handler, assume dialog is finished
    if not self.submit_handler:
      self.accept()
      return

    # let submit_handler handle submission and get optional query_worker
    query_worker = self.submit_handler(**self.data())

    # if instead of query_worker True returned, submission is successful
    # and dialog is finished
    if query_worker is True:
      self.accept()
      return

    # if no query_worker, assume submission failed and do nothing
    if not query_worker:
      return

    # if received a query_worker, execute it and handle response
    network.delayed_worker(query_worker, self.response_base,
                           self.exception_base)

  def reject_base(self):
    if self.reject_handler:
      self.reject_handler()
    self.reject()

  def response_base(self, response):
    # if no response_handler, assume dialog is finished
    if not self.response_handler:
      self.accept()
      return

    # if response_handler returned True, assume dialog is finished
    response_result = self.response_handler(response)
    if response_result:
      self.accept()

  def exception_base(self, exception):
    if hasattr(exception, 'response'):
      errors = ("{}: {}".format(k, ", ".join(v))
                for k, v in exception.response.items())
      exception_string = "\t" + "\n\t".join(errors)
    elif hasattr(exception, 'message'):
      exception_string = exception.message
    else:
      exception_string = str(exception)
    self.statusLbl.setText("Error(s) occured:\n{}".format(exception_string))
    self.statusLbl.setStyleSheet("color: red;")
    if self.exception_handler:
      self.exception_handler(exception)

  @classmethod
  def get(cls, **kwargs):
    dialog = cls(**kwargs)
    result = dialog.exec_()
    data = dialog.data()

    return data, result == QtWidgets.QDialog.Accepted


class QItemSelect(QtWidgets.QComboBox):
  def __init__(self, item, name_field='name', id_field='id', allow_none=True,
               exclude=None, default_id=None):
    super(QItemSelect, self).__init__()
    self.item = item
    self.name_field = name_field
    self.id_field = id_field
    self.allow_none = allow_none
    self.exclude = exclude
    self.default_id = default_id

    self.refresh()

  def refresh(self):
    response = network.query("GET", "collab/{}/".format(self.item), json=True)

    # copy currently selected or get default
    if self.currentIndex() == -1:
      selected_id = self.default_id
    else:
      self.currentData()

    # only clear after response is received
    self.clear()
    for idx, obj in enumerate(response):
      item_name = obj[self.name_field]
      item_id = obj[self.id_field]
      if self.exclude and (item_name in self.exclude or
                           item_id in self.exclude):
        continue

      text = "{} ({})".format(item_name, item_id)
      self.insertItem(idx, text, int(item_id))
      if item_id == selected_id:
        self.setCurrentIndex(idx)

    if self.allow_none:
      self.insertItem(0, "None", None)
    elif self.count() == 0:
      self.setEnabled(False)


class QRadioGroup(QtWidgets.QGroupBox):
  def __init__(self, title, *radios, **kwargs):
    checked = kwargs.pop('checked', None)

    super(QRadioGroup, self).__init__(title, **kwargs)

    self.radiogroup = QtWidgets.QButtonGroup()
    layout = QtWidgets.QGridLayout()
    layout.setColumnStretch(1, 1)

    for i, radio in enumerate(radios):
      radio_name, radio_id, radio_extra_controls = radio
      radio_widget = QtWidgets.QRadioButton(radio_name)
      radio_widget.setObjectName(radio_id)

      self.radiogroup.addButton(radio_widget, i)
      layout.addWidget(radio_widget, i, 0, QtCore.Qt.AlignTop)
      if radio_extra_controls is not None:
        layout.addWidget(radio_extra_controls, i, 1, QtCore.Qt.AlignTop)
        # if extra controller comes disabled, make sure it stays that way
        # and also make the radio box disabled
        if radio_extra_controls.isEnabled():
          radio_widget.toggled.connect(radio_extra_controls.setEnabled)
          radio_extra_controls.setEnabled(False)
        else:
          radio_widget.setEnabled(False)
        # if extra controller comes with a tooltip, copy that tooltip to
        # radio button itself
        if radio_extra_controls.toolTip():
          radio_widget.setToolTip(radio_extra_controls.toolTip())

      # if checked is supplied, set correct radio as checked
      # else set first radio as checked`
      if (checked is None and i == 0) or checked == radio_id:
        radio_widget.setChecked(True)

    self.setLayout(layout)

  def get_result(self):
    return self.radiogroup.checkedButton().objectName()


class QFunctionSelect(QtWidgets.QWidget):
  changed = QtCore.Signal()

  def __init__(self, text_max_length=30, **kwargs):
    super(QFunctionSelect, self).__init__(**kwargs)

    self.text_max = text_max_length

    self.label = QtWidgets.QPushButton()
    self.label.clicked.connect(self.label_clicked)
    self.label.setFlat(True)
    self.btn = QtWidgets.QPushButton("...")
    self.btn.setMaximumWidth(20)
    self.btn.clicked.connect(self.btn_clicked)

    self.set_func(idaapi.get_func(idc.ScreenEA()))

    layout = QtWidgets.QHBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(self.label)
    layout.addWidget(self.btn)
    layout.setStretch(0, 1)
    self.setLayout(layout)

  def set_func(self, func):
    self.func = func
    text = idc.GetFunctionName(self.func.startEA)
    text = text[:self.text_max] + "..." if len(text) > self.text_max else text
    self.label.setText(text)

  def label_clicked(self, checked):
    del checked
    idc.Jump(self.func.startEA)

  def btn_clicked(self, checked):
    del checked
    f = idaapi.choose_func("Choose function to match with database",
                           self.func.startEA)
    if f:
      self.set_func(f)
      self.changed.emit()


class QFunctionRangeSelect(QtWidgets.QWidget):
  def __init__(self, text_max_length=30, **kwargs):
    super(QFunctionRangeSelect, self).__init__(**kwargs)
    self.start = QFunctionSelect(text_max_length=text_max_length)
    self.start.changed.connect(self.selection_changed)
    self.end = QFunctionSelect(text_max_length=text_max_length)
    self.end.changed.connect(self.selection_changed)

    layout = QtWidgets.QGridLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(QtWidgets.QLabel("From"), 0, 0)
    layout.addWidget(QtWidgets.QLabel("To"), 1, 0)
    layout.addWidget(self.start, 0, 1)
    layout.addWidget(self.end, 1, 1)

    self.setLayout(layout)

  def selection_changed(self):
    if self.start.func.startEA < self.end.func.endEA:
      return

    start_func = self.start.func
    self.start.set_func(self.end.func)
    self.end.set_func(start_func)
