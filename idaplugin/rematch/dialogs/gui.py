from ..idasix import QtWidgets

from ida_kernwin import PluginForm
from .base import BaseDialog


class WidgetsDialog(BaseDialog):
  def __init__(self, **kwargs):
    super(WidgetsDialog, self).__init__(**kwargs)
    self.response = None
    self.statusLbl = None

    self.base_layout = QtWidgets.QVBoxLayout()

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
    cancel_btn.clicked.connect(self.reject)

  def exception_base(self, exception, traceback):
    super(WidgetsDialog, self).exception_base(exception, traceback)
    if hasattr(exception, 'errors'):
      errors = ("{}: {}".format(k, ", ".join(v))
                for k, v in exception.errors())
      exception_string = "\t" + "\n\t".join(errors)
    elif hasattr(exception, 'message'):
      exception_string = exception.message
    else:
      exception_string = str(exception)
    self.statusLbl.setText("Error(s) occured:\n{}".format(exception_string))
    self.statusLbl.setStyleSheet("color: red;")


class GuiDialog(WidgetsDialog, QtWidgets.QDialog):
  def __init__(self, title="", modal=True, **kwargs):
    super(GuiDialog, self).__init__(**kwargs)

    self.setModal(modal)
    self.setWindowTitle(title)
    self.setLayout(self.base_layout)

    self.rejected.connect(self.reject_base)
    self.accepted.connect(self.accept_base)
    self.finished.connect(self.finish_base)


class DockableDialog(WidgetsDialog, PluginForm):
  def __init__(self, title="", **kwargs):
    super(DockableDialog, self).__init__(**kwargs)
    self.title = title

  def OnCreate(self, form):
    super(DockableDialog, self).OnCreate(form)

    form = self.FormToPyQtWidget(form)

    # Set the layout when form is created
    form.setLayout(self.base_layout)

  def OnClose(self, form):
      del form
      self.finish_base(QtWidgets.QDialog.Rejected)

  def accept(self):
    self.accpet_base()
    self.Close()

  def reject(self):
    self.reject_base()
    self.Close()

  def show(self):
    self.Show(self.title)
