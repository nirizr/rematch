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
  class NestedVectorSerializer(serializers.ModelSerializer):
    class Meta:
      model = Vector
      fields = ('id', 'type', 'type_version', 'data')

  owner = serializers.ReadOnlyField(source='owner.username')
  vectors = NestedVectorSerializer(many=True, required=False)

  class Meta:
    model = Instance
    fields = ('id', 'owner', 'file', 'type', 'offset', 'vectors')

  def create(self, validated_data):
    vectors_data = validated_data.pop('vectors')
    obj = self.Meta.model.objects.create(**validated_data)
    vectors = (Vector(instance=obj, **vector_data)
               for vector_data in vectors_data)
    Vector.objects.bulk_create(vectors)
    return obj


class VectorSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vector
    fields = ('id', 'instance', 'type', 'type_version', 'data')
