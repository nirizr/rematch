from rest_framework import serializers
from collab.models import Project, File, Instance, Vector


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


class InstanceSerializer(serializers.ModelSerializer):
  owner = serializers.ReadOnlyField(source='owner.username')

  class Meta:
    model = Instance
    fields = ('id', 'owner', 'file', 'type', 'offset', 'vectors')


class VectorSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vector
    fields = ('id', 'instance', 'type', 'type_version', 'data')
