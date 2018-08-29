from . import config
from .utils import IdaKernelQueue, force_update

import ida_netnode
import ida_kernwin


class NetNode(object):
  @property
  def _nn(self):
    return ida_netnode.netnode("$rematch", 0, True)

  @IdaKernelQueue(write=True, wait=True)
  def set_bound_server(self):
    if self.validate_bound_server():
      self._nn.hashset("bound_server", str(config['login']['server']))
      force_update()

  @IdaKernelQueue(write=True, wait=True)
  def del_bound_server(self):
    self._nn.hashdel("bound_server")
    force_update()

  @IdaKernelQueue(write=True, wait=True)
  def validate_bound_server(self):
    bound_server = self._nn.hashstr('bound_server')

    # If no bound server is set for idb, we can surely set the current server
    if not bound_server:
      return True

    # If bound server matches current configuration, lets play along and set it
    # to the same value
    if bound_server == config['login']['server']:
      return True

    # otherwise, we gotta ask the user and let her decide
    msg = ("Current server is '{new_server}' while bound server for opened "
           "IDB is '{bound_server}'. Would you like to override bound server "
           "and start using currently connected server?\n"
           "This assumes data from bound server was copied to the current one."
           "\nclick Yes to bind current server or no to proceed as if file "
           "was never bound.".format(new_server=config['login']['server'],
                                     bound_server=bound_server))
    r = ida_kernwin.askbuttons_c(ida_kernwin.ASKBTN_YES, "HIDECANCEL\n" + msg)
    if r == ida_kernwin.ASKBTN_YES:
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

    return int(bound_file_id)

  @IdaKernelQueue(write=True, wait=True)
  def set_bound_file_id(self, file_id):
    success = self._nn.hashset("bound_file_id", str(file_id))
    if success:
      self.set_bound_server()
    return success

  @IdaKernelQueue(write=True, wait=True)
  def delete_bound_file_id(self):
    success = self._nn.hashdel("bound_file_id")
    if success:
      self.del_bound_server()
    return success


netnode = NetNode()
