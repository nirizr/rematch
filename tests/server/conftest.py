import pytest


@pytest.fixture(scope='session')
def django_db_use_migrations(request):
  del request
  return False
