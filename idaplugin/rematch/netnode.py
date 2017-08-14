from . import config
from utils import ida_kernel_queue

import ida_netnode
import ida_kernwin


class NetNode(object):
  @property
  def _nn(self):
    return ida_netnode.netnode("$rematch", 0, True)

  @property
  @ida_kernel_queue(wait=True)
  def bound_file_id(self):
    bound_file_id = self._nn.hashstr('bound_file_id')
    if not bound_file_id:
      return None

    if not self.validate_bound_server():
      return None

    return int(bound_file_id)

  @ida_kernel_queue(wait=True)
  def validate_bound_server(self):
    bound_server = self._nn.hashstr('bound_server')
    if not bound_server:
      self.bind_server()
      return True

    if bound_server == config['login']['server']:
      return True

    msg = ("Current server is '{}' while bound server for opened IDB is '{}'."
           "Would you like to proceed using currently connected server?\n"
           "This assumes data from bound server was copied to the current one."
           "\nclick Yes to bind current server. no to proceed as if file was "
           "never bound or once to proceed just once using current server."
           "".format(config['login']['server'], bound_server))
    r = ida_kernwin.askbuttons_c("Yes", "No", "Once", ida_kernwin.ASKBTN_YES,
                                 msg)
    if r == ida_kernwin.ASKBTN_YES:
      self.bind_server()
      return True
    elif r == ida_kernwin.ASKBTN_BTN3:
      return True
    elif r == ida_kernwin.ASKBTN_NO:
      return False

  @bound_file_id.setter
  @ida_kernel_queue(write=True, wait=True)
  def bound_file_id(self, file_id):
    r = self._nn.hashset("bound_file_id", str(file_id))
    if r:
      self.bind_server()
    return r

  @ida_kernel_queue(write=True, wait=True)
  def bind_server(self):
    self._nn.hashset("bound_server", str(config['login']['server']))

  @bound_file_id.deleter
  @ida_kernel_queue(write=True, wait=True)
  def bound_file_id(self):
    return self._nn.hashdel("bound_file_id")


netnode = NetNode()
