from django.db import models
from django.db.models.fields import files
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from .validators import idb_validator
from .strategies import strategy_choices


class Project(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, models.CASCADE, db_index=True)
  name = models.CharField(max_length=256)
  description = models.TextField()
  private = models.BooleanField()

  def __unicode__(self):
    return "Project: {}".format(self.name)
  __str__ = __unicode__

  class Meta(object):
    ordering = ('created',)


class File(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, models.CASCADE, db_index=True)
  project = models.ForeignKey(Project, models.CASCADE, null=True,
                              related_name='files')
  name = models.CharField(max_length=256)
  description = models.TextField()
  md5hash = models.CharField(max_length=32, db_index=True,
                             validators=[MinLengthValidator(32)])
  file = files.FileField(upload_to="tasks", null=True,
                         validators=[idb_validator])

  def __unicode__(self):
    return "File {}".format(self.name)
  __str__ = __unicode__


class FileVersion(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  file = models.ForeignKey(File, models.CASCADE, related_name='versions')
  md5hash = models.CharField(max_length=32,
                             validators=[MinLengthValidator(32)])

  class Meta(object):
    unique_together = (('file', 'md5hash'),)

  def __unicode__(self):
    return "File {} version {}".format(self.file.name, self.md5hash)
  __str__ = __unicode__


class Instance(models.Model):
  TYPE_EMPTY_DATA = 'empty_data'
  TYPE_DATA = 'data'
  TYPE_EMPTY_FUNCTION = 'empty_function'
  TYPE_FUNCTION = 'function'
  TYPE_CHOICES = ((TYPE_EMPTY_DATA, "Empty Data"),
                  (TYPE_DATA, "Data"),
                  (TYPE_EMPTY_FUNCTION, "Empty Function"),
                  (TYPE_FUNCTION, "Function"))

  owner = models.ForeignKey(User, models.CASCADE, db_index=True)
  file_version = models.ForeignKey(FileVersion, models.CASCADE,
                                   related_name='instances')
  type = models.CharField(max_length=64, choices=TYPE_CHOICES)
  offset = models.BigIntegerField()
  size = models.BigIntegerField()

  matches = models.ManyToManyField('self', symmetrical=False, through='Match',
                                   related_name='related_to+')

  def __unicode__(self):
    return "{} instance {} of {}".format(self.get_type_display(), self.offset,
                                         self.file_version.file.name)
  __str__ = __unicode__


class Vector(models.Model):
  TYPE_INSTRUCTION_HASH = 'instruction_hash'
  TYPE_IDENTITY_HASH = 'identity_hash'
  TYPE_NAME_HASH = 'name_hash'
  TYPE_ASSEMBLY_HASH = 'assembly_hash'
  TYPE_MNEMONIC_HASH = 'mnemonic_hash'
  TYPE_MNEMONIC_HIST = 'mnemonic_hist'
  TYPE_CHOICES = [(TYPE_INSTRUCTION_HASH, "Instruction Hash"),
                  (TYPE_IDENTITY_HASH, "Identity Hash"),
                  (TYPE_NAME_HASH, "Name Hash"),
                  (TYPE_ASSEMBLY_HASH, "Assembly Hash"),
                  (TYPE_MNEMONIC_HASH, "Mnemonic Hash"),
                  (TYPE_MNEMONIC_HIST, "Mnemonic Hist")]

  instance = models.ForeignKey(Instance, models.CASCADE,
                               related_name='vectors')
  file_version = models.ForeignKey(FileVersion, models.CASCADE,
                                   related_name='vectors')
  type = models.CharField(max_length=64, choices=TYPE_CHOICES)
  type_version = models.IntegerField()
  data = models.TextField()

  def __unicode__(self):
    return "{} vector version {} for {}".format(self.get_type_display(),
                                                self.type_version,
                                                self.instance)
  __str__ = __unicode__


class Task(models.Model):
  STATUS_PENDING = 'pending'
  STATUS_STARTED = 'started'
  STATUS_DONE = 'done'
  STATUS_FAILED = 'failed'
  STATUS_CHOICES = ((STATUS_PENDING, "Pending in Queue..."),
                    (STATUS_STARTED, "Started"),
                    (STATUS_DONE, "Done!"),
                    (STATUS_FAILED, "Failure"))

  task_id = models.UUIDField(db_index=True, null=True, unique=True,
                             editable=False)

  # store matched objects
  created = models.DateTimeField(auto_now_add=True)
  finished = models.DateTimeField(null=True)

  owner = models.ForeignKey(User, models.CASCADE, db_index=True)
  status = models.CharField(default=STATUS_PENDING, max_length=64,
                            choices=STATUS_CHOICES)

  source_file_version = models.ForeignKey(FileVersion, models.CASCADE,
                                          related_name='source_tasks')
  # TODO: make sure start > end
  source_start = models.BigIntegerField(null=True)
  source_end = models.BigIntegerField(null=True)
  # TODO: make sure only at least one of target_file/target_project is null
  target_file = models.ForeignKey(File, models.CASCADE, null=True)
  target_project = models.ForeignKey(Project, models.CASCADE, null=True)
  matchers = models.TextField(default='[]')
  strategy = models.CharField(choices=strategy_choices(), max_length=256,
                              default='all_strategy')

  progress = models.PositiveSmallIntegerField(default=0)
  progress_max = models.PositiveSmallIntegerField(null=True)


class Match(models.Model):
  from_instance = models.ForeignKey(Instance, models.CASCADE,
                                    related_name='from_matches')
  to_instance = models.ForeignKey(Instance, models.CASCADE,
                                  related_name='to_matches')

  task = models.ForeignKey(Task, models.CASCADE, db_index=True,
                           related_name='matches')

  type = models.CharField(max_length=64, choices=Vector.TYPE_CHOICES)
  score = models.FloatField()


class Annotation(models.Model):
  TYPE_NAME = 'name'
  TYPE_ASSEMBLY = 'assembly'
  TYPE_PROTOTYPE = 'prototype'
  TYPE_CHOICES = ((TYPE_NAME, "Name"),
                  (TYPE_ASSEMBLY, "Assembly"),
                  (TYPE_PROTOTYPE, "Prototype"))

  instance = models.ForeignKey(Instance, models.CASCADE,
                               related_name='annotations')
  type = models.CharField(max_length=64, choices=TYPE_CHOICES)
  data = models.TextField()
