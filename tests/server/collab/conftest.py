import pytest
from rest_framework import test


@pytest.fixture
def api_client():
  return test.APIClient()


@pytest.fixture
def admin_api_client(admin_user):
  client = test.APIClient()
  client.force_authenticate(user=admin_user)
  return client
