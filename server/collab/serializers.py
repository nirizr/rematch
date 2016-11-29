from rest_framework import serializers
from collab.models import Project, File, Task, Instance, Vector, Match


class ProjectSerializer(serializers.ModelSerializer):
  owner = serializers.ReadOnlyField(source='owner.username')
  created = serializers.ReadOnlyField()

  class Meta:
    model = Project
    fields = ('id', 'created', 'owner', 'name', 'description', 'private',
              'files')


class FileSerializer(serializers.ModelSerializer):
  owner = serializers.ReadOnlyField(source='owner.username')
  created = serializers.ReadOnlyField()

  class Meta:
    model = File
    fields = ('id', 'created', 'owner', 'project', 'name', 'description',
              'md5hash', 'file', 'instances')


class TaskSerializer(serializers.ModelSerializer):
  owner = serializers.ReadOnlyField(source='owner.username')
  task_id = serializers.ReadOnlyField()
  created = serializers.ReadOnlyField()
  finished = serializers.ReadOnlyField()
  status = serializers.ReadOnlyField()
  progress = serializers.ReadOnlyField()
  progress_max = serializers.ReadOnlyField()

  class Meta:
    model = Task
    fields = ('id', 'task_id', 'created', 'finished', 'owner', 'status',
              'target_project', 'target_file', 'source_file', 'source_start',
              'source_end', 'progress', 'progress_max')


class TaskEditSerializer(TaskSerializer):
  target_project = serializers.ReadOnlyField()
  target_file = serializers.ReadOnlyField()
  source_file = serializers.ReadOnlyField()
  source_start = serializers.ReadOnlyField()
  source_end = serializers.ReadOnlyField()


class InstanceSerializer(serializers.ModelSerializer):
  class NestedVectorSerializer(serializers.ModelSerializer):
    class Meta:
      model = Vector
      fields = ('id', 'type', 'type_version', 'data')

  owner = serializers.ReadOnlyField(source='owner.username')
  vectors = NestedVectorSerializer(many=True, required=True)

  class Meta:
    model = Instance
    fields = ('id', 'owner', 'file', 'type', 'offset', 'vectors')

  def create(self, validated_data):
    vectors_data = validated_data.pop('vectors')
    obj = self.Meta.model.objects.create(**validated_data)
    vectors = (Vector(instance=obj, file=validated_data['file'], **vector_data)
               for vector_data in vectors_data)
    Vector.objects.bulk_create(vectors)
    return obj


class VectorSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vector
    fields = ('id', 'file', 'instance', 'type', 'type_version', 'data')


class MatchSerializer(serializers.ModelSerializer):
  class Meta:
    model = Match
    fields = ('task', 'type', 'score')
