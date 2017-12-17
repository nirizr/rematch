from rest_framework import (viewsets, permissions, mixins, decorators, status,
                            response)
from collab.models import (Project, File, FileVersion, Task, Instance, Vector,
                           Match, Annotation)
from collab.serializers import (ProjectSerializer, FileSerializer,
                                FileVersionSerializer, TaskSerializer,
                                TaskEditSerializer, InstanceVectorSerializer,
                                VectorSerializer, MatchSerializer,
                                SlimInstanceSerializer, AnnotationSerializer,
                                MatcherSerializer, StrategySerializer)
from collab.permissions import IsOwnerOrReadOnly
from collab import tasks
from collab.matchers import matchers_list
from collab.strategies import strategies_list


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


class ProjectViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer
  filter_fields = ('created', 'owner', 'name', 'description', 'private')


class FileViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer
  filter_fields = ('created', 'owner', 'project', 'name', 'description',
                   'md5hash')

  @decorators.detail_route(url_path="file_version/(?P<md5hash>[0-9A-Fa-f]+)",
                           methods=['GET', 'POST'])
  def file_version(self, request, pk, md5hash):
    del pk
    file_obj = self.get_object()

    if request.method == 'POST':
      file_version, created = \
        FileVersion.objects.get_or_create(md5hash=md5hash, file=file_obj)
    else:
      file_version = FileVersion.objects.get(md5hash=md5hash, file=file_obj)
      created = False

    serializer = FileVersionSerializer(file_version)

    resp_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    response_data = serializer.data
    response_data['newly_created'] = created
    return response.Response(response_data, status=resp_status)


class FileVersionViewSet(viewsets.ModelViewSet):
  queryset = FileVersion.objects.all()
  serializer_class = FileVersionSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filter_fields = ('id', 'file', 'md5hash')


class TaskViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin, mixins.ListModelMixin,
                  viewsets.GenericViewSet):
  queryset = Task.objects.all()
  permission_classes = (permissions.IsAuthenticated, IsOwnerOrReadOnly)
  filter_fields = ('task_id', 'created', 'finished', 'owner', 'status')

  def perform_create(self, serializer):
    task = serializer.save(owner=self.request.user)
    tasks.match.delay(task_id=task.id)

  def get_serializer_class(self):
    serializer_class = TaskSerializer
    if self.request.method in ('PATCH', 'PUT'):
      serializer_class = TaskEditSerializer
    return serializer_class

  @decorators.detail_route(url_path="locals")
  def locals(self, request, pk):
    del request
    del pk

    task = self.get_object()

    # include local matches (created for specified file_version and are a
    # 'from_instance' match). for those, include the match objects themselves
    queryset = Instance.objects.filter(from_matches__task=task).distinct()

    # pagination code
    page = self.paginate_queryset(queryset)
    if page is not None:
      serializer = SlimInstanceSerializer(page, many=True)
      return self.get_paginated_response(serializer.data)

    serializer = SlimInstanceSerializer(queryset, many=True)
    return response.Response(serializer.data)

  @decorators.detail_route(url_path="remotes")
  def remotes(self, request, pk):
    del request
    del pk

    task = self.get_object()

    # include remote matches (are a 'to_instance' match), those are referenced
    # by match records of local instances
    queryset = Instance.objects.filter(to_matches__task=task).distinct()

    # pagination code
    page = self.paginate_queryset(queryset)
    if page is not None:
      serializer = SlimInstanceSerializer(page, many=True)
      return self.get_paginated_response(serializer.data)

    serializer = SlimInstanceSerializer(queryset, many=True)
    return response.Response(serializer.data)

  @decorators.detail_route(url_path="matches")
  def matches(self, request, pk):
    del request
    del pk

    task = self.get_object()

    queryset = Match.objects.filter(task=task)

    # pagination code
    page = self.paginate_queryset(queryset)
    if page is not None:
      serializer = MatchSerializer(page, many=True)
      return self.get_paginated_response(serializer.data)

    serializer = MatchSerializer(queryset, many=True)
    return response.Response(serializer.data)


class MatchViewSet(viewsets.ReadOnlyModelViewSet):
  queryset = Match.objects.all()
  serializer_class = MatchSerializer
  filter_fields = ('task', 'type', 'score')

  @staticmethod
  @decorators.list_route()
  def matchers(request):
    del request
    if any((m.is_abstract() for m in matchers_list)):
      raise Exception("Abstract matcher in list")
    serializer = MatcherSerializer(matchers_list, many=True)
    return response.Response(serializer.data)

  @staticmethod
  @decorators.list_route()
  def strategies(request):
    del request
    if any((s.is_abstract() for s in strategies_list)):
      raise Exception("Abstract strategy in list")
    serializer = StrategySerializer(strategies_list, many=True)
    return response.Response(serializer.data)


class InstanceViewSet(ViewSetManyAllowedMixin, ViewSetOwnerMixin,
                      viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  serializer_class = InstanceVectorSerializer
  filter_fields = ('owner', 'file_version', 'type')


class VectorViewSet(ViewSetManyAllowedMixin, viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filter_fields = ('instance', 'file_version', 'type', 'type_version')

  @staticmethod
  def perform_create(serializer):
    file_version = serializer.validated_data['instance'].file_version
    serializer.save(file_version=file_version)


class AnnotationViewSet(viewsets.ModelViewSet):
  queryset = Annotation.objects.all()
  serializer_class = AnnotationSerializer
  filter_fields = ('instance', 'type', 'data')
