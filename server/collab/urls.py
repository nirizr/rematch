from django.conf.urls import include, url
from collab import views
from rest_framework.routers import DefaultRouter

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'projects', views.ProjectViewSet)
router.register(r'files', views.FileViewSet)
router.register(r'tasks', views.TaskViewSet)
router.register(r'instances', views.InstanceViewSet)
router.register(r'vectors', views.VectorViewSet)

urlpatterns = [
  url(r'^', include(router.urls)),
]
