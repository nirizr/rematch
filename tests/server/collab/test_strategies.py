import pytest
from rest_framework import status

from utils import assert_response

from collab import strategies


def test_get_strategy_failure():
  with pytest.raises(Exception) as ex:
    strategies.get_strategy('nonexistant_strategy')
    assert "Couldn't find requested strategy" in ex.msg


def test_strategies(admin_client):
  response = admin_client.get('/collab/matches/strategies/',
                              content_type="application/json")
  assert_response(response, status.HTTP_200_OK, strategies.strategies_list)


def test_strategies_abstract(admin_client):
  strategies.strategies_list.append(strategies.Strategy)

  with pytest.raises(Exception) as ex:
    admin_client.get('/collab/matches/strategies/',
                     content_type="application/json")
  assert ex.value.args[0] == "Abstract strategy in list"
