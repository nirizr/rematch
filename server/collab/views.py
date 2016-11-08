from rest_framework import viewsets, permissions, mixins
from collab.models import Project, File, Task, Instance, Vector
from collab.serializers import (ProjectSerializer, FileSerializer,
                                TaskSerializer, TaskEditSerializer,
                                InstanceSerializer, VectorSerializer)
from collab.permissions import IsOwnerOrReadOnly
from collab import tasks


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


class ProjectViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer


class FileViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer


class TaskViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin, mixins.ListModelMixin,
                  viewsets.GenericViewSet):
  queryset = Task.objects.all()
  serializer_class = TaskSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    result = tasks.match.delay()
    serializer.save(owner=self.request.user, task_id=result.id)

  def get_serializer_class(self):
    serializer_class = self.serializer_class
    if self.request.method in ('PATCH', 'PUT'):
      serializer_class = TaskEditSerializer
    return serializer_class


class InstanceViewSet(ViewSetManyAllowedMixin, ViewSetOwnerMixin,
                      viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  serializer_class = InstanceSerializer


class VectorViewSet(ViewSetManyAllowedMixin, viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,)

  @staticmethod
  def perform_create(serializer):
    serializer.save(file=serializer.validated_data['instance'].file)
