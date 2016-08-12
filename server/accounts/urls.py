from django.conf.urls import include, url
from . import views

urlpatterns = [
  url(r'^profile/$', views.profile, name='profile'),
  url(r'', include('rest_auth.urls')),
]
