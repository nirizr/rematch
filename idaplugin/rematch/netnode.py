from . import config
from utils import IdaKernelQueue, force_update

import ida_netnode
import ida_kernwin


class NetNode(object):
  @property
  def _nn(self):
    return ida_netnode.netnode("$rematch", 0, True)

  @IdaKernelQueue(write=True, wait=True)
  def set_bound_server(self):
    self._nn.hashset("bound_server", str(config['login']['server']))
    force_update()

  @IdaKernelQueue(write=True, wait=True)
  def del_bound_server(self):
    self._nn.hashdel("bound_server")
    force_update()

  @IdaKernelQueue(wait=True)
  def validate_bound_server(self):
    bound_server = self._nn.hashstr('bound_server')
    if not bound_server:
      self.set_bound_server()
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
      self.set_bound_server()
      return True
    elif r == ida_kernwin.ASKBTN_BTN3:
      return True
    elif r == ida_kernwin.ASKBTN_NO:
      return False

  @property
  def bound_file_id(self):
    return self.getter_bound_file_id()

  @bound_file_id.setter
  def bound_file_id(self, file_id):
    if file_id is None:
      self.delete_bound_file_id()
    else:
      self.set_bound_file_id(file_id)

  @bound_file_id.deleter
  def bound_file_id(self):
    self.delete_bound_file_id()

  @IdaKernelQueue(wait=True)
  def getter_bound_file_id(self):
    bound_file_id = self._nn.hashstr('bound_file_id')
    if not bound_file_id:
      return None

    if not self.validate_bound_server():
      return None

    return int(bound_file_id)

  @IdaKernelQueue(write=True, wait=True)
  def set_bound_file_id(self, file_id):
    success = self._nn.hashset("bound_file_id", str(file_id))
    if success:
      self.set_bound_server()
    force_update()
    return success

  @IdaKernelQueue(write=True, wait=True)
  def delete_bound_file_id(self):
    success = self._nn.hashdel("bound_file_id")
    if success:
      self.del_bound_server()
    return success


netnode = NetNode()
