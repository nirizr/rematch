import pytest
from rest_framework import status

from utils import assert_response

from collab import matchers


def test_matchers(admin_client):
  response = admin_client.get('/collab/matches/matchers/',
                              content_type="application/json")
  assert_response(response, status.HTTP_200_OK, matchers.matchers_list)


def test_matchers_abstract(admin_client):
  matchers.matchers_list.append(matchers.Matcher)

  with pytest.raises(Exception) as ex:
    admin_client.get('/collab/matches/matchers/',
                     content_type="application/json")
  assert ex.value.args[0] == "Abstract matcher in list"
