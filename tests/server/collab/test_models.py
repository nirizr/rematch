import pytest
from rest_framework import status

from utils import (create_model, setup_model, assert_eq, assert_response,
                   collab_models_keys)


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

  # Manually handle matches, where API does not allow creation or
  # modification of objects, as they're read only
  if model_name == "matches":
    assert_response(response, status.HTTP_405_METHOD_NOT_ALLOWED)
    return

  assert_response(response, status.HTTP_201_CREATED)
  projects_created = [response.data]

  response = admin_api_client.get('/collab/{}/'.format(model_name),
                                  HTTP_ACCEPT="application/json")
  assert_eq(response.data, projects_created)


def test_full_hierarchy(admin_api_client, admin_user):
  dependency = create_model('dependencies', admin_user)
  dependency.save()

  response = admin_api_client.get('/collab/annotations/full_hierarchy/',
                                  data={'ids': dependency.dependent.id},
                                  HTTP_ACCEPT='application/json')

  expected_response = [dependency.dependency, dependency.dependent]
  assert_eq(response.data, expected_response)


@pytest.mark.django_db
def test_file_fileversion(admin_client, admin_user):
  fv_obj = create_model('file_versions', admin_user)
  fv_obj.save()

  url = '/collab/files/{}/file_version/{}/'.format(fv_obj.file_id,
                                                   fv_obj.md5hash)

  response = admin_client.get(url, content_type="application/json")
  assert_response(response, status.HTTP_200_OK, fv_obj)

  fv_obj.complete = True
  fv_obj.save()
  response = admin_client.get(url, content_type="application/json")
  assert_response(response, status.HTTP_200_OK, fv_obj)
