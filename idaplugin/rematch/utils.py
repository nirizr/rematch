import os
import functools

import idc
import ida_kernwin


def get_plugin_base(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", *path)


def get_plugin_path(*path):
  return get_plugin_base("rematch", *path)


class ida_kernel_queue(object):
  """Force functions to run in IDA's main thread.

  Access to IDA's IDB database is not thread-safe, so access should only be
  done from IDA's main thread, or IDB corruption and unpredictable results may
  occour.

  This decorator is used to transparently force functions to run in IDA's main
  thread. If a function decorated by `ida_kernel_queue` is called from within
  IDA's main thread, it will simply be executed immidiately by
  `ida_kernwin.execute_sync`. Otherwise it'll be queued into IDA's main thread
  work queue, and will either block or return immidiately depending on the
  `wait` argument.

  Because execute_sync is only returning integers, we use the decorator class'
  context to store the return value temporarily from within the function
  executed in IDA's main thread context, and pick it back out in the original
  function's context. Thanks to python's GIL, synchronization and thread-safety
  it is guaranteed to work.
  """

  def __init__(self, write=False, wait=False):
    self.wait = wait
    self.reqf = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    if not self.wait:
      self.reqf |= ida_kernwin.MFF_NOWAIT

    self.__ret = None
    self.called = False

  def __call__(self, callback):
    if self.called:
      raise Exception("Can't be called twice!")
    self.called = True

    @functools.wraps(callback)
    def enqueue(*args, **kwargs):
      def partial_callback():
        # Store return value inside main thread, return a positive value
        self.__ret = callback(*args, **kwargs)
        return 1

      # enqueue partial_callback to be executed by IDA's main thread is needed
      ida_kernwin.execute_sync(partial_callback, self.reqf)

      # retreive return value and set sync variable to None for safety
      ret, self.__ret = self.__ret, None
      return ret

    return enqueue
