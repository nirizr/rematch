import pytest


collab_model_names = ['projects', 'files', 'tasks', 'instances', 'vectors']


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_model_names)
def test_empty_lists(client, model_name):
  response = client.get('/collab/{}/'.format(model_name))
  assert response.status_code is 200
  json_response = response.json()
  assert json_response == []
