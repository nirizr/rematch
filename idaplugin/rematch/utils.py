import os
import functools

import logger

import idc
import ida_kernwin


def get_plugin_base(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", *path)


def get_plugin_path(*path):
  return get_plugin_base("rematch", *path)


class ida_kernel_queue(object):
  def __init__(self, write=False, wait=False):
    self.wait = wait
    self.reqf = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    if not self.wait:
      self.reqf |= ida_kernwin.MFF_NOWAIT

  def __call__(self, callback):
    @functools.wraps(callback)
    def enqueue(*args, **kwargs):
      partial_callback = functools.partial(callback, *args, **kwargs)
      r = ida_kernwin.execute_sync(partial_callback, self.reqf)
      if r == -1:
        msg = ("Possible failure in queueing for main thread with callback: "
               "{}, reqf: {}, args: {}, kwargs: {}".format(callback, self.reqf,
                                                           args, kwargs))
        logger.log('ida_main').warn(msg)
      elif self.wait:
        return r

    return enqueue
