from django.contrib.auth.models import User
# flake8: noqa
# this is a hack.
# http://stackoverflow.com/questions/30027203/create-django-super-user-in-a-docker-container-without-inputting-password:
User.objects.create_superuser('admin', 'admin@rematch.re', 'qwe123')
