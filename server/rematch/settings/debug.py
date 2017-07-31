from rematch.settings.base import *  # noqa

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# As of django 1.10, allowed hosts are validated in debug as well,
# this disables that and makes sure all hosts are acceptible when
# running in debug mode. for more details see
# https://docs.djangoproject.com/en/1.10/ref/settings/
# for security implications see
# https://docs.djangoproject.com/en/1.10/topics/security/ \
# #host-headers-virtual-hosting
ALLOWED_HOSTS = ['*']
