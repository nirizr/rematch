from rest_framework import serializers
from collab.models import (Project, File, FileVersion, Task, Instance, Vector,
                           Match)


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
              'md5hash', 'file')


class FileVersionSerializer(serializers.ModelSerializer):
  class Meta:
    model = FileVersion
    fields = ('id', 'created', 'file', 'md5hash')


class TaskSerializer(serializers.ModelSerializer):
  owner = serializers.ReadOnlyField(source='owner.username')
  source_file = serializers.ReadOnlyField(source='source_file_version.file_id')
  task_id = serializers.ReadOnlyField()
  created = serializers.ReadOnlyField()
  finished = serializers.ReadOnlyField()
  status = serializers.ReadOnlyField()
  progress = serializers.ReadOnlyField()
  progress_max = serializers.ReadOnlyField()

  class Meta:
    model = Task
    fields = ('id', 'task_id', 'created', 'finished', 'owner', 'status',
              'target_project', 'target_file', 'source_file',
              'source_file_version', 'source_start', 'source_end', 'progress',
              'progress_max')


class TaskEditSerializer(TaskSerializer):
  target_project = serializers.ReadOnlyField()
  target_file = serializers.ReadOnlyField()
  source_file = serializers.ReadOnlyField()
  source_file_version = serializers.ReadOnlyField()
  source_start = serializers.ReadOnlyField()
  source_end = serializers.ReadOnlyField()


class InstanceSerializer(serializers.ModelSerializer):
  class NestedVectorSerializer(serializers.ModelSerializer):
    class Meta:
      model = Vector
      fields = ('id', 'type', 'type_version', 'data')

  owner = serializers.ReadOnlyField(source='owner.username')
  file = serializers.ReadOnlyField(source='file_version.file_id')
  vectors = NestedVectorSerializer(many=True, required=True)

  class Meta:
    model = Instance
    fields = ('id', 'owner', 'file', 'file_version', 'type', 'offset',
              'vectors')

  def create(self, validated_data):
    vectors_data = validated_data.pop('vectors')
    file_version = validated_data['file_version']

    obj = self.Meta.model.objects.create(**validated_data)
    vectors = (Vector(instance=obj, file_version=file_version,
                      file=file_version.file, **vector_data)
               for vector_data in vectors_data)
    Vector.objects.bulk_create(vectors)
    return obj


class VectorSerializer(serializers.ModelSerializer):
  file = serializers.ReadOnlyField(source='file_version.file_id')

  class Meta:
    model = Vector
    fields = ('id', 'file', 'file_version', 'instance', 'type', 'type_version',
              'data')

  def create(self, validated_data):
    file = validated_data['file_version'].file
    return self.Meta.model.objects.create(file=file, **validated_data)


class MatchSerializer(serializers.ModelSerializer):
  class Meta:
    model = Match
    fields = ('task', 'type', 'score')
