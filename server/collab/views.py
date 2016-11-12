from rest_framework import viewsets, permissions, mixins
from collab.models import Project, File, Task, Instance, Vector, Match
from collab.serializers import (ProjectSerializer, FileSerializer,
                                TaskSerializer, TaskEditSerializer,
                                InstanceSerializer, VectorSerializer,
                                MatchSerializer)
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
  filter_fields = ('created', 'owner', 'name', 'description', 'private')


class FileViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer
  filter_fields = ('created', 'owner', 'project', 'name', 'description',
                   'md5hash')


class TaskViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin, mixins.ListModelMixin,
                  viewsets.GenericViewSet):
  queryset = Task.objects.all()
  serializer_class = TaskSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,
                        IsOwnerOrReadOnly)
  filter_fields = ('task_id', 'created', 'finished', 'owner', 'status')

  def perform_create(self, serializer):
    result = tasks.match.delay()
    serializer.save(owner=self.request.user, task_id=result.id)

  def get_serializer_class(self):
    serializer_class = self.serializer_class
    if self.request.method in ('PATCH', 'PUT'):
      serializer_class = TaskEditSerializer
    return serializer_class


class MatchViewSet(viewsets.ReadOnlyModelViewSet):
  queryset = Match.objects.all()
  serializer_class = MatchSerializer
  filter_fields = ('task', 'type', 'score')


class InstanceViewSet(ViewSetManyAllowedMixin, ViewSetOwnerMixin,
                      viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  serializer_class = InstanceSerializer
  filter_fields = ('owner', 'file', 'type')


class VectorViewSet(ViewSetManyAllowedMixin, viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
  filter_fields = ('instance', 'file', 'type', 'type_version')

  @staticmethod
  def perform_create(serializer):
    serializer.save(file=serializer.validated_data['instance'].file)
