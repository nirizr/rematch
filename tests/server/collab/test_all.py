import pytest
from rest_framework import status
import json

from utils import (rand_hash, create_model, setup_model, assert_eq,
                   assert_response, collab_models_keys)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_guest_list_empty(api_client, model_name):
  response = api_client.get('/collab/{}/'.format(model_name),
                            HTTP_ACCEPT='application/json')
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_list_empty(admin_api_client, model_name):
  response = admin_api_client.get('/collab/{}/'.format(model_name),
                                  HTTP_ACCEPT='application/json')
  assert_response(response, status.HTTP_200_OK, [])


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_guest_list(api_client, admin_user, model_name):
  # setup objects
  obj = create_model(model_name, admin_user)
  obj.save()

  response = api_client.get('/collab/{}/'.format(model_name),
                            HTTP_ACCEPT="application/json")
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_list(admin_api_client, admin_user, model_name):
  # setup objects
  obj = create_model(model_name, admin_user)
  obj.save()

  response = admin_api_client.get('/collab/{}/'.format(model_name),
                                  HTTP_ACCEPT="application/json")
  assert_response(response, status.HTTP_200_OK, [obj])


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_guest_creation(api_client, admin_user, model_name):
  model_data = setup_model(model_name, admin_user)

  response = api_client.post('/collab/{}/'.format(model_name),
                             data=model_data,
                             HTTP_ACCEPT="application/json")
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models_keys)
def test_model_creation(admin_api_client, admin_user, model_name):
  model_data = setup_model(model_name, admin_user)

  response = admin_api_client.post('/collab/{}/'.format(model_name),
                                   data=model_data,
                                   HTTP_ACCEPT='application/json')

  assert_response(response, status.HTTP_201_CREATED)
  projects_created = [response.data]

  response = admin_api_client.get('/collab/{}/'.format(model_name),
                                  HTTP_ACCEPT="application/json")
  assert_eq(response.data, projects_created)


# TODO: move to its own file
def test_template(admin_client):
  response = admin_client.get('/accounts/profile/')
  assert_response(response, status.HTTP_200_OK)

  user_data = json.loads(response.data)
  assert 'id' in user_data
  assert 'username' in user_data
  assert 'email' in user_data
  assert 'is_authenticated' in user_data
  assert user_data['is_authenticated'] is True
  assert 'is_active' in user_data
  assert user_data['is_active'] is True
  assert 'is_staff' in user_data
  assert user_data['is_staff'] is True
  assert 'is_superuser' in user_data
  assert user_data['is_superuser'] is True


@pytest.mark.django_db
def test_file_fileversion(admin_client, admin_user):
  file_obj = create_model('files', admin_user)
  file_obj.save()

  file_version = rand_hash(32)
  url = '/collab/files/{}/file_version/{}/'.format(file_obj.id, file_version)

  response = admin_client.post(url, content_type="application/json")
  obj = {'newly_created': True, 'md5hash': file_version, 'file': file_obj.id}
  assert_response(response, status.HTTP_201_CREATED, obj)

  response = admin_client.get(url, content_type="application/json")
  obj = {'newly_created': False, 'md5hash': file_version, 'file': file_obj.id}
  assert_response(response, status.HTTP_200_OK, obj)


@pytest.mark.parametrize('limit', [None, 10])
@pytest.mark.parametrize('resource', ['locals', 'remotes', 'matches'])
def test_task_resource_empty(resource, limit, admin_client, admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  data = {'limit': limit} if limit else {}
  response = admin_client.get('/collab/tasks/{}/{}/'.format(task.id, resource),
                              data=data, content_type="application/json")
  assert_response(response, status.HTTP_200_OK, [])


def test_task(admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  from collab.tasks import match
  match(task.id)
