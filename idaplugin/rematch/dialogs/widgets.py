from ..idasix import QtWidgets, QtCore

import ida_funcs
import ida_kernwin
import idc

from .. import network


class QItem(object):
  def __init__(self, item, name_field, id_field, description_field,
               exclude=None, columns=3, selected=None, empty_disabled=True,
               **kwargs):
    super(QItem, self).__init__(**kwargs)
    self.item = item
    self.name_field = name_field
    self.id_field = id_field
    self.description_field = description_field
    self.exclude = exclude
    self.columns = columns
    self.selected = selected
    self.empty_disabled = empty_disabled

    self.found_selection = False
    self.load()

  def load(self):
    response = network.query("GET", "collab/{}/".format(self.item), json=True)

    for i, obj in enumerate(response):
      if not obj:
        continue
      item_name = obj[self.name_field]
      item_description = obj[self.description_field]
      item_id = obj[self.id_field]

      if self.exclude and (item_name in self.exclude or
                           item_id in self.exclude):
        continue

      item = self.create_item(i=i, item_name=item_name, item_id=item_id,
                              item_description=item_description)
      self.addWidget(item, i / self.columns, i % self.columns)

      if self.selected:
        selected = (item_name in self.selected or item_id in self.selected or
                    self.selected == "all")
        self.set_selected(i, selected)
        if selected:
          self.found_selection = True

    if self.count() == 0 and self.empty_disabled:
      self.setEnabled(False)

    if self.selected is None and self.count() > 0:
      self.set_selected(0, True)


class QItemSelect(QItem, QtWidgets.QComboBox):
  def __init__(self, *args, **kwargs):
    self.allow_none = kwargs.pop('allow_none', False)
    super(QItemSelect, self).__init__(*args, **kwargs)

    if self.selected and not self.found_selection:
      self.insertItem(0, "UNKNOWN ({})".format(self.selected), self.selected)
      self.set_selected(0, True)
      self.found_selection = True

    if self.allow_none:
      self.insertItem(0, "None", None)
      if not self.found_selection:
        self.set_selected(0, True)

  @staticmethod
  def create_item(i, item_name, item_id, item_description):
    del i
    # TODO: include the item description as tooltip
    del item_description
    text = "{} ({})".format(item_name, item_id)
    return (text, item_id)

  def addWidget(self, item, row, col):
    del row, col
    text, item_id = item
    self.addItem(text, item_id)

  def set_selected(self, i, selected):
    if selected:
      self.setCurrentIndex(i)


class QItemCheckBoxes(QItem, QtWidgets.QGridLayout):
  def create_item(self, item_name, item_id, item_description, **kwargs):
    del kwargs
    widget = QtWidgets.QCheckBox(item_name)
    widget.id = item_id
    if item_description:
      widget.setToolTip(item_description)
    return widget

  def set_selected(self, i, selected):
    self.itemAt(i).widget().setChecked(selected)

  def get_result(self):
    return [self.itemAt(i).widget().id
              for i in range(self.count())
              if self.itemAt(i).widget().isChecked()]


class QRadioLayout(QtWidgets.QGridLayout):
  def __init__(self, *radios, **kwargs):
    super(QRadioLayout, self).__init__(**kwargs)

    self.radiogroup = QtWidgets.QButtonGroup()
    self.setColumnStretch(1, 1)
    self.create_items(radios)

  def create_items(self, radios):
    for i, radio_details in enumerate(radios):
      item_widget = self.create_item(i, *radio_details)
      self.addWidget(item_widget, i, 0, QtCore.Qt.AlignTop)

  def create_item(self, i, item_name, item_id, item_description, *args):
    del args
    item_widget = QtWidgets.QRadioButton(item_name)
    item_widget.setObjectName(item_id)
    item_widget.setToolTip(item_description)

    self.radiogroup.addButton(item_widget, i)

    return item_widget

  def set_selected(self, i, selected):
    self.radiogroup.button(i).setChecked(selected)

  def get_result(self):
    return self.radiogroup.checkedButton().objectName()


class QRadioExtraLayout(QRadioLayout):
  def create_item(self, i, item_name, item_id, item_description, *args):
    # slightly ugly to have overriden create_item to have the same parameters
    item_extra, selected = args
    item = super(QRadioExtraLayout, self).create_item(i, item_name, item_id,
                                                      item_description)
    self.set_selected(i, selected)

    if item_extra:
      self.update_item_extra(item, item_extra)
      self.addWidget(item_extra, i, 1, QtCore.Qt.AlignTop)

    return item

  @staticmethod
  def update_item_extra(item_widget, item_extra):
    # if extra controller comes disabled, make sure it stays that way
    # and also make the radio box disabled
    if item_extra.isEnabled():
      item_widget.toggled.connect(item_extra.setEnabled)
      item_extra.setEnabled(False)
    else:
      item_widget.setEnabled(False)
    # if item_extra controller comes with a tooltip, copy that tooltip to
    # radio button itself
    if item_extra.toolTip():
      item_widget.setToolTip(item_extra.toolTip())


class QItemRadioGroup(QItem, QRadioLayout):
  # TODO: cehck the multi inheritence
  # TODO: check the extra param passed to create_item from load()
  # TODO: make sure this is reasonavble and working
  pass


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
