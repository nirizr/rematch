import ida_kernwin

import json

from .. idasix import QtGui, QtWidgets, QtCore

from . import gui, widgets
from .. import network
from .. import exceptions

from .. import collectors

from . import scriptfilter
from . import serializedgraph


class ResultDialog(gui.DockableDialog):
  MATCH_NAME_COLUMN = 0
  CHECKBOX_COLUMN = 0
  MATCH_SCORE_COLUMN = 1
  ANNOTATION_COUNT_COLUMN = 2
  MATCH_KEY_COLUMN = 3

  LOCAL_ELEMENT_COLOR = QtGui.QBrush(QtGui.QColor(0x42, 0x86, 0xF4))
  LOCAL_ELEMENT_TOOLTIP = "Local function"
  REMOTE_ELEMENT_TOOLTIP = "Remote function"

  def __init__(self, *args, **kwargs):
    super(ResultDialog, self).__init__(title="Match results", *args, **kwargs)

    self.apply_pbar = None
    self.matched_map = {}
    self.applied_annotations = set()

    self.filter_dialog = None
    self.graph_dialog = serializedgraph.SerializedGraphDialog()

    # buttons
    self.btn_set = QtWidgets.QPushButton('&Select best')
    self.btn_clear = QtWidgets.QPushButton('&Clear')
    self.btn_filter = QtWidgets.QPushButton('Fi&lter')
    self.btn_apply = QtWidgets.QPushButton('&Apply Matches')

    size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                        QtWidgets.QSizePolicy.Fixed)
    self.btn_set.setSizePolicy(size_policy)
    self.btn_clear.setSizePolicy(size_policy)
    self.btn_filter.setSizePolicy(size_policy)
    self.btn_apply.setSizePolicy(size_policy)

    # buttons layout
    self.hlayoutButtons = QtWidgets.QHBoxLayout()
    self.hlayoutButtons.addWidget(self.btn_set)
    self.hlayoutButtons.addWidget(self.btn_clear)
    self.hlayoutButtons.addWidget(self.btn_filter)
    self.hlayoutButtons.addWidget(self.btn_apply)

    self.btn_set.clicked.connect(self.set_checks)
    self.btn_clear.clicked.connect(self.clear_checks)
    self.btn_filter.clicked.connect(self.show_filter)
    self.btn_apply.clicked.connect(self.apply_matches)

    # matches tree
    self.search_box = QtWidgets.QLineEdit()
    self.tree = widgets.SearchTreeWidget(search_box=self.search_box,
                                         match_column=self.MATCH_NAME_COLUMN)

    # tree columns
    self.tree.setHeaderLabels(("Function", "Score", "Annotation #", "Engine"))

    self.tree.header().setDefaultSectionSize(20)
    self.tree.resizeColumnToContents(self.MATCH_SCORE_COLUMN)
    self.tree.resizeColumnToContents(self.ANNOTATION_COUNT_COLUMN)
    self.tree.setColumnWidth(self.MATCH_NAME_COLUMN, 150)

    # other tree properties
    self.tree.setFrameShape(QtWidgets.QFrame.NoFrame)
    self.tree.setAlternatingRowColors(True)
    self.tree.setSortingEnabled(True)
    self.tree.sortItems(self.MATCH_SCORE_COLUMN, QtCore.Qt.DescendingOrder)

    # prgoress bar
    self.progress = QtWidgets.QProgressBar()
    self.statusLbl = QtWidgets.QLabel()

    # base layout
    self.base_layout.addWidget(self.tree)
    self.base_layout.addWidget(self.search_box)
    self.base_layout.addWidget(self.statusLbl)
    self.base_layout.addWidget(self.progress)
    self.base_layout.addLayout(self.hlayoutButtons)

    # connect events to handle
    self.tree.itemChanged.connect(self.item_changed)
    self.tree.itemSelectionChanged.connect(self.item_selection_changed)

  def show(self):
    self.graph_dialog.Show()
    super(ResultDialog, self).show()

  def reset_focus(self):
    # calling graph_dialog.show gave it focus. taking it back now
    super(ResultDialog, self).show()
    self.tree.setFocus()

  def item_selection_changed(self):
    local_item = None
    remote_item = None

    if not self.tree.selectedItems():
      return

    if len(self.tree.selectedItems()) != 1:
      return

    item = self.tree.selectedItems()[0]
    if item.parent() is None:
      local_item = item
    else:
      local_item = item.parent()
      remote_item = item

    if local_item:
      ida_kernwin.jumpto(self.action.get_obj(local_item.api_id)['offset'])
      self.reset_focus()

    if remote_item:
      # TODO: change graph to a "loading..." message
      q = network.QueryWorker("GET", "collab/annotations/", json=True,
                              params={"type": "assembly",
                                      "instance": remote_item.api_id})
      q.start(self.handle_display_change)

  def handle_display_change(self, response):
    if not len(response) == 1:
      raise exceptions.ServerException()

    nodes = json.loads(response[0]['data'])
    self.graph_dialog.SetNodes(nodes)
    self.graph_dialog.Show()
    self.reset_focus()

  def item_changed(self, item, column):
    if not column == self.CHECKBOX_COLUMN:
      return

    parent = item.parent()
    if parent is None:
      return

    self.tree.blockSignals(True)
    for curr_child in self.enumerate_children(parent):
      if item != curr_child:
        curr_child.setCheckState(self.CHECKBOX_COLUMN, QtCore.Qt.Unchecked)
    self.tree.blockSignals(False)

  def show_filter(self):
    self.filter_dialog = scriptfilter.FilterDialog()
    self.filter_dialog.accepted.connect(self.update_filter)
    self.filter_dialog.show()

  def update_filter(self):
    filter_code = self.filter_dialog.get_code()
    self.action.apply_filter(filter_code)
    self.filter_dialog = None

  def enumerate_children(self, root=None):
    if not root:
      root = self.tree.invisibleRootItem()
    for child_index in range(root.childCount()):
      yield root.child(child_index)

  def enumerate_items(self):
    for local_item in self.enumerate_children():
      for remote_item in self.enumerate_children(local_item):
        yield local_item, remote_item

  def items_count(self):
    return sum(1 for _ in self.enumerate_items())

  def apply_matches(self):
    self.matched_map = {}
    self.applied_annotations = set()

    for local_item, remote_item in self.enumerate_items():
      if remote_item.checkState(self.CHECKBOX_COLUMN):
        local_offset = self.action.get_obj(local_item.api_id)['offset']
        if remote_item.api_id in self.matched_map:
          self.matched_map[remote_item.api_id].append(local_offset)
        else:
          self.matched_map[remote_item.api_id] = [local_offset]

    item_count = sum(len(m) for m in self.matched_map.values())
    if not item_count:
      return

    self.apply_pbar = QtWidgets.QProgressDialog("", "&Cancel", 0, item_count)

    # TODO: optimize this query
    q = network.QueryWorker("GET", "collab/annotations/full_hierarchy",
                            params={"instance": self.matched_map.keys()},
                            json=True, splittable="instance")
    q.start(self.handle_apply_matches, write=True)

  def handle_apply_matches(self, response):
    for annotation in response:
      remote_id = annotation['instance']
      local_offsets = self.matched_map[remote_id]

      # TODO: move dependency handling/applying loops and logic to the
      # annotation apply code
      for dependency in annotation['dependencies']:
        self.apply_annotations(dependency, None)

      self.apply_annotation(annotation, *local_offsets)
      self.apply_pbar.setValue(self.apply_pbar.value() + len(local_offsets))

  def apply_annotation(self, annotation, *local_offsets):
    if annotation['id'] in self.applied_annotations:
      return
    self.applied_annotations.add(annotation['id'])

    for local_offset in local_offsets:
      collectors.apply(local_offset, annotation)
      # TODO: raise exception on failure

  def clear_checks(self):
    for _, remote_item in self.enumerate_items():
      del _
      remote_item.setCheckState(self.CHECKBOX_COLUMN, QtCore.Qt.Unchecked)

  def set_checks(self):
    for local_item in self.enumerate_children():
      checked = False
      for remote_item in self.enumerate_children(local_item):
        if remote_item.checkState(self.CHECKBOX_COLUMN):
          checked = True
          break

      # If no child/remote item is checked, check the first one
      if not checked and local_item.childCount():
        remote_item = local_item.child(0)
        remote_item.setCheckState(self.CHECKBOX_COLUMN, QtCore.Qt.Checked)

  def populate_item(self, parent_item, item_obj, match_obj=None):
    if parent_item is None:
      parent_item = self.tree

    item_id = item_obj['id']
    item_name = item_obj['name']

    tree_item = widgets.MatchTreeWidgetItem(item_id, parent_item)
    item_flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
    if match_obj:
      item_flags |= QtCore.Qt.ItemIsUserCheckable

    tree_item.setFlags(item_flags)
    tree_item.setText(self.MATCH_NAME_COLUMN, item_name)

    if parent_item == self.tree:
      tree_item.setForeground(self.MATCH_NAME_COLUMN,
                                self.LOCAL_ELEMENT_COLOR)
      tree_item.setToolTip(self.MATCH_NAME_COLUMN,
                             self.LOCAL_ELEMENT_TOOLTIP)
    else:
      tree_item.setToolTip(self.MATCH_NAME_COLUMN,
                             self.REMOTE_ELEMENT_TOOLTIP)
      self.tree.expandItem(parent_item)

      # fake click on first child item so browser won't show a blank page
      # TODO: This doesn't work (probably because signal to actually perform
      # the action is blocked), but if signals arent blocked IDA hangs
      # probably because network query
      # if not self.tree.selectedItems():
      #   tree_item.setSelected(True)

    if match_obj:
      tree_item.setText(self.MATCH_SCORE_COLUMN,
                          str(round(match_obj['score'], 2)))
      tree_item.setText(self.ANNOTATION_COUNT_COLUMN,
                          str(item_obj['annotation_count']))
      tree_item.setText(self.MATCH_KEY_COLUMN,
                          str(match_obj['type']))
      tree_item.setCheckState(self.CHECKBOX_COLUMN, QtCore.Qt.Unchecked)

    return tree_item
