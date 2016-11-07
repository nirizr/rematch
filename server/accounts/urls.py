from django.conf.urls import include, url
from . import views

urlpatterns = [
  url(r'^profile/$', views.profile, name='profile'),
  url(r'', include('rest_auth.urls')),
  url(r'', include('registration.backends.default.urls')),
  # url('^/', include('django.contrib.auth.urls')),
]
