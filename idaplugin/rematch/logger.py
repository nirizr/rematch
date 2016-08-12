import logging

logging.basicConfig()


def logger(module):
  from . import config
  logger = logging.getLogger(module)
  if 'debug' in config and config['debug']:
    logger.setLevel(logging.DEBUG)
  return logger
