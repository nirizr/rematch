from rest_framework import viewsets, permissions
from collab.models import Project, File, Instance, Vector
from collab.serializers import (ProjectSerializer, FileSerializer,
                                InstanceSerializer, VectorSerializer)
from collab.permissions import IsOwnerOrReadOnly


class ProjectViewSet(viewsets.ModelViewSet):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class FileViewSet(viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class InstanceViewSet(viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  serializer_class = InstanceSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)

  def get_serializer(self, *args, **kwargs):
    if "data" in kwargs:
      data = kwargs["data"]

      if isinstance(data, list):
        kwargs["many"] = True

    return super(InstanceViewSet, self).get_serializer(*args, **kwargs)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class VectorViewSet(viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,)

  def get_serializer(self, *args, **kwargs):
    if "data" in kwargs:
      data = kwargs["data"]

      if isinstance(data, list):
        kwargs["many"] = True

    return super(VectorViewSet, self).get_serializer(*args, **kwargs)
