import pytest
import json
from functools import partial
from rest_framework import status

from django.db import models
from collab.models import Project, File, Task, Instance, Vector


collab_models = {'projects': {'name': 'test_project_1', 'private': False,
                              'description': 'description_1', 'files': []},
                 'files': {'instances': [], 'md5hash': 'H' * 32,
                           'name': 'file1', 'description': 'desc1'},
                 'tasks': {'source_file': 1, 'target_project': 1},
                 'instances': {'offset': 0, 'type': 'function', 'file': 1,
                               'vectors': []},
                 'vectors': {'instance': 1, 'type': 'hash', 'type_version': 0,
                             'data': 'data'}}

collab_model_objects = {'projects': partial(Project, private=False),
                        'files': partial(File, name='name', description='desc',
                                         md5hash='H' * 32),
                        'tasks': Task,
                        'instances': partial(Instance, offset=0),
                        'vectors': partial(Vector, type='hash', data='data',
                                           type_version=0)}

collab_model_reqs = {'projects': {},
                     'files': {},
                     'tasks': {'target_project': 'projects',
                               'source_file': 'files'},
                     'instances': {'file': 'files'},
                     'vectors': {'file': 'files',
                                 'instance': 'instances'}}


def resolve_reqs(model_name, user):
  model_reqs = collab_model_reqs[model_name]

  for req_field, req_model in model_reqs.items():
    obj = collab_model_objects[req_model]()

    create_model(req_model, user, base_obj=obj)

    obj.owner = user
    obj.save()
    print("Created model: {} ({}) at {}".format(obj, obj.id, req_field))
    yield req_field, obj


def create_model(model_name, user, base_obj=None):
  if base_obj is None:
    base_obj = collab_model_objects[model_name]()
  base_obj.owner = user

  for req_field, obj in resolve_reqs(model_name, user):
    base_obj.__setattr__(req_field, obj)

  print(base_obj)
  return base_obj


def setup_model(model_name, user):
  model_dict = collab_models[model_name]

  for req_field, obj in resolve_reqs(model_name, user):
    model_dict[req_field] = obj.id

  print(model_dict)
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


def assert_response(response, status):
  print(response.content)
  assert response.status_code == status


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_empty_lists(client, model_name):
  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK)
  json_response = response.json()
  assert json_response == []


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_model_guest_list(client, admin_user, model_name):
  # setup objects
  obj = create_model(model_name, admin_user)
  obj.save()

  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK)
  dct_list = response.json()
  dct = dct_list[-1]
  assert_eq(dct, obj)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name, model_data', collab_models.items())
def test_model_guest_creation(client, model_name, model_data):
  response = client.post('/collab/{}/'.format(model_name),
                         data=json.dumps(model_data),
                         content_type="application/json")
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name, model_data', collab_models.items())
def test_model_creation(client, admin_client, admin_user, model_name,
                        model_data):
  model_data = setup_model(model_name, admin_user)

  response = admin_client.post('/collab/{}/'.format(model_name),
                               data=json.dumps(model_data),
                               content_type="application/json")

  assert_response(response, status.HTTP_201_CREATED)
  projects_created = [response.json()]

  response = client.get('/collab/{}/'.format(model_name))
  assert_eq(response.json(), projects_created)
