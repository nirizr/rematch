import pytest
from rest_framework import status

from utils import create_model, assert_response


@pytest.mark.parametrize('limit', [None, 10])
@pytest.mark.parametrize('resource', ['locals', 'remotes', 'matches'])
def test_task_resource_empty(resource, limit, admin_client, admin_user):
  task = create_model('tasks', admin_user)
  task.save()

  data = {'limit': limit} if limit else {}
  response = admin_client.get('/collab/tasks/{}/{}/'.format(task.id, resource),
                              data=data, content_type="application/json")
  assert_response(response, status.HTTP_200_OK, [])


@pytest.mark.parametrize('additional_fields', [{},
                                               {'source_start': 1000},
                                               {'source_end': 1000},
                                               {'target_file': 'files'}])
def test_task(admin_user, additional_fields):
  task = create_model('tasks', admin_user, **additional_fields)
  task.save()

  from collab.tasks import match
  match(task.id)


def test_task_nonexistant_matcher(admin_user):
  task = create_model('tasks', admin_user, matchers='["nonexistant_matcher"]')
  task.save()

  from collab.tasks import match
  with pytest.raises(ValueError) as ex:
    match(task.id)
  assert 'Unfamiliar matchers were requested' in ex.value.args[0]
