#!/bin/sh 
script="
from django.contrib.auth.models import User;

usern = '$USER';
password = '$PASS';
email = '$MAIL';

if User.objects.filter(username=username).count() == 0:
    u = User(username=usern)
    u.set_password(password)
    u.is_superuser = True
    u.is_staff = True
    u.save()
else:
    print('Superuser creation skipped.');
"
printf "$script" | python manage.py shell
