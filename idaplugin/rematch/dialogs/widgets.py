from ..idasix import QtWidgets, QtCore

import ida_funcs
import ida_kernwin
import idc

from .. import network


class QItemSelect(QtWidgets.QComboBox):
  def __init__(self, item, name_field='name', id_field='id', allow_none=True,
               exclude=None, default_id=None, **kwargs):
    super(QItemSelect, self).__init__(**kwargs)
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
      selected_id = self.currentData()

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


class QItemCheckBoxes(QtWidgets.QGridLayout):
  def __init__(self, item, name_field='name', id_field='id',
               description_field='description', exclude=None, columns=3):
    super(QItemCheckBoxes, self).__init__()
    self.item = item
    self.name_field = name_field
    self.id_field = id_field
    self.description_field = description_field
    self.exclude = exclude
    self.columns = columns
    self.checkboxes = []

    self.refresh()

  def refresh(self):
    response = network.query("GET", "collab/{}/".format(self.item), json=True)

    self.checkboxes = []
    for i, obj in enumerate(response):
      if not obj:
        continue
      item_name = obj[self.name_field]
      item_description = obj[self.description_field]
      item_id = obj[self.id_field]

      if self.exclude and (item_name in self.exclude or
                           item_id in self.exclude):
        continue

      checkbox_widget = QtWidgets.QCheckBox(item_name)
      if item_description:
        checkbox_widget.setToolTip(item_description)
      checkbox_widget.id = item_id
      checkbox_widget.setChecked(True)
      self.addWidget(checkbox_widget, i / self.columns, i % self.columns)
      self.checkboxes.append(checkbox_widget)

  def get_result(self):
    return [cb.id for cb in self.checkboxes if cb.isChecked()]


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
    self.func = None

    self.label = QtWidgets.QPushButton()
    self.label.clicked.connect(self.label_clicked)
    self.label.setFlat(True)
    self.btn = QtWidgets.QPushButton("...")
    self.btn.setMaximumWidth(20)
    self.btn.clicked.connect(self.btn_clicked)

    current_func = ida_funcs.get_func(idc.ScreenEA())
    if current_func:
      self.set_func(current_func)

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
    f = ida_kernwin.choose_func("Choose function to match with database",
                                self.func.startEA if self.func else 0)
    if f:
      self.set_func(f)
      self.changed.emit()

  def get_result(self):
    return self.func.startEA if self.func else None


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
    if not self.start.func or not self.end.func:
      return

    if self.start.func.startEA < self.end.func.endEA:
      return

    start_func = self.start.func
    self.start.set_func(self.end.func)
    self.end.set_func(start_func)

  def get_result(self):
    return [self.start.func.startEA if self.start.func else None,
            self.start.func.endEA if self.start.func else None]


class MatchTreeWidgetItem(QtWidgets.QTreeWidgetItem):
  def __init__(self, api_id, *args, **kwargs):
    super(MatchTreeWidgetItem, self).__init__(*args, **kwargs)
    self.api_id = api_id

  def __lt__(self, other):
    column = self.treeWidget().sortColumn()
    if self.childCount() == 0 and other.childCount() == 0:
      try:
        return float(self.text(column)) < float(other.text(column))
      except ValueError:
        return self.text(column) < other.text(column)
    elif self.childCount() == 0 and other.childCount() > 0:
      return True
    elif self.childCount() > 0 and other.childCount() == 0:
      return False
    else:
      my_biggest_child = self.biggest_child()
      other_biggest_child = other.biggest_child()
      return my_biggest_child < other_biggest_child

  def biggest_child(self):
    return max(self.child(i) for i in range(self.childCount()))


class SearchTreeWidget(QtWidgets.QTreeWidget):
  def __init__(self, search_box, match_column, *args, **kwargs):
    super(SearchTreeWidget, self).__init__(*args, **kwargs)
    self.search_box = search_box
    self.match_column = match_column
    self.search_box.textEdited.connect(self.search)
    self.search_box.returnPressed.connect(self.search)

  def keyPressEvent(self, event):  # noqa: N802
    if event.text():
      self.search_box.keyPressEvent(event)
    else:
      super(SearchTreeWidget, self).keyPressEvent(event)

  def search(self, _=None):
    del _

    text = self.search_box.text().lower()
    start = self.currentItem()
    it = QtWidgets.QTreeWidgetItemIterator(self.currentItem())
    it += 1
    while it.value() != start:
      if it.value() is None:
        it = QtWidgets.QTreeWidgetItemIterator(self.topLevelItem(0))
      if text in it.value().text(self.match_column).lower():
        self.setCurrentItem(it.value())
        self.scrollToItem(it.value())
        return
      it += 1
