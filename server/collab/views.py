from logging import getLogger
import functools

from rest_framework import (viewsets, permissions, decorators, response,
                            pagination, status)

from django.db import models
from django.http import Http404

import django_cte

from collab.models import (Project, File, FileVersion, Task, Instance, Vector,
                           Match, Annotation, Dependency)
from collab.serializers import (ProjectSerializer, FileSerializer,
                                FileVersionSerializer, TaskSerializer,
                                TaskEditSerializer, InstanceVectorSerializer,
                                VectorSerializer, MatchSerializer,
                                SlimInstanceSerializer, AnnotationSerializer,
                                MatcherSerializer, StrategySerializer,
                                DependencySerializer, CountInstanceSerializer)
from collab.permissions import IsOwnerOrReadOnly
from collab import tasks
from collab.matchers import matchers_list
from collab.strategies import strategies_list
from collab.filters import InstanceFilter


class ViewSetOwnerMixin(object):
  permission_classes = (permissions.IsAuthenticated, IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class ViewSetManyAllowedMixin(object):
  def get_serializer(self, *args, **kwargs):
    if "data" in kwargs:
      data = kwargs["data"]

      if isinstance(data, list):
        kwargs["many"] = True

    return super(ViewSetManyAllowedMixin, self).get_serializer(*args, **kwargs)


class DefaultPagination(pagination.CursorPagination):
    page_size = 100
    page_size_query_param = 'page_size'


def paginatable(serializer_cls):
  def decorator(f):
    @functools.wraps(f)
    def wraps(self, request, *args, **kwargs):
      queryset = f(self, request=request, *args, **kwargs)
      paged = self.paginate_queryset(queryset)
      if paged is not None:
        serializer = serializer_cls(paged, many=True,
                                    context={'request': request})
        return self.get_paginated_response(serializer.data)
      else:
        serializer = serializer_cls(queryset, many=True,
                                    context={'request': request})
        return response.Response(serializer.data)
    return wraps
  return decorator


class ProjectViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer
  filterset_fields = ('created', 'owner', 'name', 'description', 'private')


class FileViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer
  filterset_fields = ('created', 'owner', 'project', 'name', 'description',
                      'md5hash')

  @staticmethod
  @decorators.action(detail=True,
                     url_path="file_version/(?P<md5hash>[0-9A-Fa-f]{32})")
  def current(request, pk, md5hash):
    del request
    file_version = (FileVersion.objects.filter(md5hash=md5hash, file=pk,
                                               complete=True)
                                       .order_by('-created').first())
    if file_version is None:
      raise Http404("No matching complete FileVersion available")
    serializer = FileVersionSerializer(instance=file_version)
    return response.Response(data=serializer.data)


class FileVersionViewSet(viewsets.ModelViewSet):
  queryset = FileVersion.objects.all()
  serializer_class = FileVersionSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('id', 'file', 'md5hash', 'complete')

  def create(self, request, *args, **kwargs):
    # Delete file verion if force creation was requested
    if request.GET.get('force', False):
      internal_val = self.get_serializer().to_internal_value(data=request.data)
      r = self.queryset.filter(file=internal_val['file'],
                               md5hash=internal_val['md5hash']).delete()
      getLogger('fileversion.create').info("deletion: %s", r)

    return super(FileVersionViewSet, self).create(request, *args, **kwargs)


class TaskViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = Task.objects.all()
  filterset_fields = ('task_id', 'created', 'finished', 'owner', 'status')

  def perform_create(self, serializer):
    task = serializer.save(owner=self.request.user)
    tasks.match.delay(task_id=task.id)

  def get_serializer_class(self):
    # Limit editable fields if performing an update
    serializer_class = TaskSerializer
    if self.request.method in ('PATCH', 'PUT'):
      serializer_class = TaskEditSerializer
    return serializer_class


class MatchViewSet(viewsets.ReadOnlyModelViewSet):
  queryset = Match.objects.all()
  serializer_class = MatchSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('task', 'type', 'score')
  pagination_class = DefaultPagination

  @staticmethod
  @decorators.action(detail=False)
  def matchers(request):
    del request
    if any((m.is_abstract() for m in matchers_list)):
      raise Exception("Abstract matcher in list")
    serializer = MatcherSerializer(matchers_list, many=True)
    return response.Response(serializer.data)

  @staticmethod
  @decorators.action(detail=False)
  def strategies(request):
    del request
    if any((s.is_abstract() for s in strategies_list)):
      raise Exception("Abstract strategy in list")
    serializer = StrategySerializer(strategies_list, many=True)
    return response.Response(serializer.data)


class InstanceViewSet(ViewSetManyAllowedMixin, ViewSetOwnerMixin,
                      viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  pagination_class = DefaultPagination
  filterset_class = InstanceFilter

  def get_serializer_class(self):
    # use full instance serializer when receiving data
    if self.request.GET.get('annotation_count', False):
      return CountInstanceSerializer
    elif (self.request.method in ('PATCH', 'PUT', 'POST') or
          self.request.GET.get('full', False)):
      return InstanceVectorSerializer
    return SlimInstanceSerializer

  def create(self, request, *args, **kwargs):
    # Create as we're supposed to, but avoid triggering a serializer.data
    # access, as those require pulling a lot of data from the db as well as
    # serializing and sending a lot of data
    del args, kwargs
    serializer = self.get_serializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    self.perform_create(serializer)
    return response.Response({}, status=status.HTTP_201_CREATED)


class VectorViewSet(ViewSetManyAllowedMixin, viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('instance', 'file_version', 'type', 'type_version')

  @staticmethod
  def perform_create(serializer):
    file_version = serializer.validated_data['instance'].file_version
    serializer.save(file_version=file_version)


class AnnotationViewSet(viewsets.ModelViewSet):
  queryset = Annotation.objects.all()
  serializer_class = AnnotationSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('instance', 'type', 'data')

  @decorators.action(detail=False)
  @paginatable(AnnotationSerializer)
  def full_hierarchy(self, request):
    del self

    instance_ids = request.query_params.getlist('instance')

    # TODO: perhaps only provide needed IDs here and fetch them using a
    # second query?
    def make_cte_subquery(cte):
      value0 = models.expressions.Value(0, output_field=models.IntegerField())
      value1 = models.expressions.Value(1, output_field=models.IntegerField())
      return (Annotation.objects.filter(instance__in=instance_ids)
              # .values("uuid", "instance", "type", "data",
              .values("id", "uuid", depth=value0)
              .union(cte.join(Annotation, dependents=cte.col.uuid)
                        .values("id", "uuid", depth=cte.col.depth + value1),
                     all=True))

    cte = django_cte.With.recursive(make_cte_subquery)

    annotations = (cte.join(Annotation, id=cte.col.id)
                      .with_cte(cte)
                      .annotate(depth=cte.col.depth)
                      .order_by("-depth"))

    return annotations


class DependencyViewSet(viewsets.ModelViewSet):
  queryset = Dependency.objects.all()
  serializer_class = DependencySerializer
  permission_classes = (permissions.IsAuthenticated,)
