from rest_framework import status

from utils import assert_response


def test_template(admin_client):
  response = admin_client.get('/accounts/profile/')
  assert_response(response, status.HTTP_200_OK)

  assert 'id' in response.data
  assert 'username' in response.data
  assert 'email' in response.data
  assert 'is_authenticated' in response.data
  assert response.data['is_authenticated'] is True
  assert 'is_active' in response.data
  assert response.data['is_active'] is True
  assert 'is_staff' in response.data
  assert response.data['is_staff'] is True
  assert 'is_superuser' in response.data
  assert response.data['is_superuser'] is True
