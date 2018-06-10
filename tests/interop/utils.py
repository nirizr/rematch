import inspect


def collector_types(module, attr):
  for _, obj in inspect.getmembers(module):
    if inspect.isclass(obj) and hasattr(obj, attr):
      yield getattr(obj, attr)


def model_types(model):
  for type_name, text in model.TYPE_CHOICES:
    yield type_name
