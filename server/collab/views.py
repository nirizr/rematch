from rest_framework import viewsets, permissions
from collab.models import Project, File, Instance, Vector
from collab.serializers import (ProjectSerializer, FileSerializer,
                                InstanceSerializer, VectorSerializer)
from collab.permissions import IsOwnerOrReadOnly


class ViewSetOwnerMixin(object):
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class ViewSetManyAllowedMixin(object):
  def get_serializer(self, *args, **kwargs):
    if "data" in kwargs:
      data = kwargs["data"]

      if isinstance(data, list):
        kwargs["many"] = True

    return super(ViewSetManyAllowedMixin, self).get_serializer(*args, **kwargs)


class ProjectViewSet(viewsets.ModelViewSet, ViewSetOwnerMixin):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer


class FileViewSet(viewsets.ModelViewSet, ViewSetOwnerMixin):
  queryset = File.objects.all()
  serializer_class = FileSerializer


class InstanceViewSet(viewsets.ModelViewSet, ViewSetOwnerMixin,
                      ViewSetManyAllowedMixin):
  queryset = Instance.objects.all()
  serializer_class = InstanceSerializer


class VectorViewSet(viewsets.ModelViewSet, ViewSetManyAllowedMixin):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
