# flake8: noqa
# this is a hack.
# http://stackoverflow.com/questions/6244382/how-to-automate-createsuperuser-on-django
echo "from django.contrib.auth.models import User; User.objects.filter(email='admin@remat.ch').delete(); User.objects.create_superuser('admin@remat.ch', 'admin', 'qwe123')" | python manage.py shell
