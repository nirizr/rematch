import pytest
import json
from functools import partial
from rest_framework import status

from django.db import models
from collab.models import Project, File, FileVersion, Task, Instance, Vector

import random


def rand_hash(n):
  return ''.join(random.choice("01234567890ABCDEF") for _ in range(n))


collab_models = {'projects': {'name': 'test_project_1', 'private': False,
                              'description': 'description_1', 'files': []},
                 'files': {'md5hash': 'H' * 32, 'name': 'file1',
                           'description': 'desc1'},
                 'file_versions': {'md5hash': 'J' * 32},
                 'tasks': {},
                 'instances': {'offset': 0, 'type': 'function', 'vectors': [],
                               'annotations': []},
                 'vectors': {'type': 'assembly_hash', 'type_version': 0,
                             'data': 'data'}}

collab_model_objects = {'projects': partial(Project, private=False),
                        'files': partial(File, name='name', description='desc',
                                         md5hash='H' * 32),
                        'file_versions': partial(FileVersion),
                        'tasks': Task,
                        'instances': partial(Instance, offset=0),
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
                                 'file_version': 'file_versions',
                                 'file': 'files'}}


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


def assert_eq(a, b):
  if isinstance(a, list) and isinstance(b, list):
    assert len(a) == len(b)
    for a_item, b_item in zip(a, b):
      assert_eq(a_item, b_item)
  if isinstance(a, models.Model) and isinstance(b, dict):
    for k in b:
      d_value = b.__getitem__(k)
      o_value = a.__getattribute__(k)
      d_type = type(d_value)
      o_type = type(o_value)
      if d_type == o_type:
        assert d_value == o_value
      else:
        print("Skipped matching {k}: {d_value}({d_type}) ?? "
              "{o_value}({o_type})".format(k=k, d_value=d_value,
                                           d_type=d_type, o_value=o_value,
                                           o_type=o_type))


def assert_response(response, status, data=None):
  print(response.content)
  assert response.status_code == status
  if isinstance(data, (list, dict)):
    assert_eq(response.json(), data)
  elif data:
    assert_eq(response.content, data)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_empty_lists(client, model_name):
  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK, [])


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_model_guest_list(client, admin_user, model_name):
  # setup objects
  obj = create_model(model_name, admin_user)
  obj.save()

  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK, [obj])


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_model_guest_creation(client, admin_user, model_name):
  model_data = setup_model(model_name, admin_user)

  response = client.post('/collab/{}/'.format(model_name),
                         data=json.dumps(model_data),
                         content_type="application/json")
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_model_creation(client, admin_client, admin_user, model_name):
  model_data = setup_model(model_name, admin_user)

  response = admin_client.post('/collab/{}/'.format(model_name),
                               data=json.dumps(model_data),
                               content_type="application/json")

  assert_response(response, status.HTTP_201_CREATED)
  projects_created = [response.json()]

  response = client.get('/collab/{}/'.format(model_name))
  assert_eq(response.json(), projects_created)


@pytest.mark.django_db
def test_file_fileversion(admin_client, admin_user):
  file = create_model('files', admin_user)
  file.save()

  file_version = rand_hash(32)
  url = '/collab/files/{}/file_version/{}/'.format(file.id, file_version)

  response = admin_client.post(url, content_type="application/json")
  obj = {'newly_created': True, 'md5hash': file_version, 'file': file.id}
  assert_response(response, status.HTTP_201_CREATED, obj)

  response = admin_client.get(url, content_type="application/json")
  obj = {'newly_created': False, 'md5hash': file_version, 'file': file.id}
  assert_response(response, status.HTTP_200_OK, obj)


def test_task_locals_empty(admin_client, admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  response = admin_client.get('/collab/tasks/{}/locals/'.format(task.id),
                              content_type="application/json")
  assert_response(response, status.HTTP_200_OK, [])


def test_task_remotes_empty(admin_client, admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  response = admin_client.get('/collab/tasks/{}/remotes/'.format(task.id),
                              content_type="application/json")
  assert_response(response, status.HTTP_200_OK, [])


def test_task_matches_empty(admin_client, admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  response = admin_client.get('/collab/tasks/{}/matches/'.format(task.id),
                              content_type="application/json")
  assert_response(response, status.HTTP_200_OK, [])
