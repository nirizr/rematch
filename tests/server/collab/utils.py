from functools import partial

from django.db import models
from collab.models import Project, File, FileVersion, Task, Instance, Vector
from collab.matchers import matchers_list

import random
import json
import inspect
from dateutil.parser import parse as parse_date


try:
  strtypes = (str, unicode)
  inttypes = (int, long)
except NameError:
  strtypes = str
  inttypes = int


def rand_hash(n):
  return ''.join(random.choice("01234567890ABCDEF") for _ in range(n))


requested_matchers = json.dumps([m.match_type for m in matchers_list])

collab_models = {'projects': {'name': 'test_project_1', 'private': False,
                              'description': 'description_1', 'files': []},
                 'files': {'md5hash': 'H' * 32, 'name': 'file1',
                           'description': 'desc1'},
                 'file_versions': {'md5hash': 'J' * 32},
                 'tasks': {},
                 'instances': {'offset': 0, 'type': 'function', 'size': 0,
                               'vectors': [], 'annotations': []},
                 'vectors': {'type': 'assembly_hash', 'type_version': 0,
                             'data': 'data'}}

collab_models_keys = collab_models.keys()

collab_model_objects = {'projects': partial(Project, private=False),
                        'files': partial(File, name='name', description='desc',
                                         md5hash='H' * 32),
                        'file_versions': partial(FileVersion),
                        'tasks': partial(Task, matchers=requested_matchers),
                        'instances': partial(Instance, offset=0, size=0),
                        'vectors': partial(Vector, type='assembly_hash',
                                           data='data', type_version=0),
                        'rand_hash': partial(rand_hash, 32)}

collab_model_reqs = {'projects': {},
                     'files': {},
                     'file_versions': {'file': 'files',
                                       'md5hash': 'rand_hash'},
                     'tasks': {'target_project': 'projects',
                               'source_file_version': 'file_versions'},
                     'instances': {'file_version': 'file_versions'},
                     'vectors': {'instance': 'instances',
                                 'file_version': 'file_versions'}}


def resolve_reqs(model_name, user):
  model_reqs = collab_model_reqs[model_name]

  for req_field, req_model in model_reqs.items():
    obj = collab_model_objects[req_model]()

    create_model(req_model, user, base_obj=obj)

    if isinstance(obj, models.Model):
      obj.owner = user
      obj.save()
      print("Created model: {} ({}) at {}".format(obj, obj.id, req_field))
    yield req_field, obj


def create_model(model_name, user, base_obj=None):
  if base_obj is None:
    base_obj = collab_model_objects[model_name]()

  if isinstance(base_obj, models.Model):
    base_obj.owner = user

    for req_field, obj in resolve_reqs(model_name, user):
      base_obj.__setattr__(req_field, obj)

  print("base_obj", base_obj)
  return base_obj


def setup_model(model_name, user):
  model_dict = collab_models[model_name]

  for req_field, obj in resolve_reqs(model_name, user):
    if isinstance(obj, models.Model):
      model_dict[req_field] = obj.id
    else:
      model_dict[req_field] = obj

  print("model_dict", model_dict)
  return model_dict


def simplify_object(obj):
  try:
    obj = parse_date(obj)
  except (AttributeError, ValueError, TypeError):
    pass
  try:
    obj = obj.replace(microsecond=0, tzinfo=None).isoformat()
  except (AttributeError, TypeError):
    pass
  return obj


def assert_eq(a, b):
  a, b = simplify_object(a), simplify_object(b)
  print(a, b)
  if isinstance(a, list) and isinstance(b, list):
    assert len(a) == len(b)
    for a_item, b_item in zip(a, b):
      assert_eq(a_item, b_item)
  elif isinstance(a, dict) and isinstance(b, dict):
    # intentionally only iterate over keys from b
    for k in b.keys():
      assert_eq(a[k], b[k])
  elif isinstance(b, dict) and (isinstance(a, models.Model) or
                                inspect.isclass(a)):
    assert_eq(b, a)
  elif isinstance(a, dict) and (isinstance(b, models.Model) or
                                inspect.isclass(b)):
    for k in a:
      # TODO: serializer-added values cannot be validated, so we'll have to
      # ignore any attribute that does not exist in Model object
      if not hasattr(b, k):
        print("Ignoring missing model parameter: {} in {}".format(k, b))
        continue
      a_value = a.__getitem__(k)
      b_value = getattr(b, k)
      assert_eq(a_value, b_value)
  elif isinstance(a, inttypes) and isinstance(b, models.Model):
    assert_eq(a, b.id)
  elif isinstance(a, strtypes) and isinstance(b, models.Model):
    assert_eq(a, b.username)
  elif b.__class__.__name__ == 'RelatedManager':
    assert_eq(a, list(b.all()))
  else:
    assert a == b


def assert_response(response, status, data=None):
  print(response.content)
  assert response.status_code == status
  if data is None:
    pass
  elif isinstance(data, (list, dict)):
    if 'results' in response.data:
      assert_eq(response.data['results'], data)
    else:
      assert_eq(response.data, data)
  elif data:
    assert_eq(response.content, data)
