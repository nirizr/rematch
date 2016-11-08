from django.db import models
from django.db.models.fields import files
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from collab.validators import IdbValidator


class Project(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=256)
  description = models.TextField()
  private = models.BooleanField()

  def __unicode__(self):
    return "Project: {}".format(self.name)
  __str__ = __unicode__

  class Meta:
    ordering = ('created',)


class File(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, db_index=True)
  project = models.ForeignKey(Project, null=True, related_name='files')
  name = models.CharField(max_length=256)
  description = models.TextField()
  md5hash = models.CharField(max_length=32, db_index=True,
                             validators=[MinLengthValidator(32)])
  file = files.FileField(upload_to="tasks", null=True,
                         validators=[IdbValidator])

  def __unicode__(self):
    return "File {}".format(self.name)
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

  owner = models.ForeignKey(User, db_index=True)
  file = models.ForeignKey(File, related_name='instances')
  type = models.CharField(max_length=16, choices=TYPE_CHOICES)
  offset = models.BigIntegerField()

  matches = models.ManyToManyField('self', symmetrical=False, through='Match',
                                   related_name='related_to+')

  def __unicode__(self):
    return "{} instance {} at {}".format(self.get_type_display(), self.offset,
                                         self.file.name)
  __str__ = __unicode__


class Vector(models.Model):
  DUMMY = 'dummy'
  TYPE_HASH = 'hash'
  TYPE_ASSEMBLY_HASH = 'assembly_hash'
  TYPE_MNEMONIC_HASH = 'mnemonic_hash'
  TYPE_MNEMONIC_HIST = 'mnemonic_hist'
  TYPE_OPCODE_HIST = 'opcode_histogram'
  TYPE_CHOICES = ((DUMMY, "Dummy"),
                  (TYPE_HASH, "Hash"),
                  (TYPE_ASSEMBLY_HASH, "Assembly Hash"),
                  (TYPE_MNEMONIC_HASH, "Mnemonic Hash"),
                  (TYPE_MNEMONIC_HIST, "Mnemonic Hist"),
                  (TYPE_OPCODE_HIST, "Opcode Histogram"))

  instance = models.ForeignKey(Instance, related_name='vectors')
  file = models.ForeignKey(File, related_name='vectors')
  type = models.CharField(max_length=16, choices=TYPE_CHOICES)
  type_version = models.IntegerField()
  data = models.TextField()

  matches = models.ManyToManyField('self', symmetrical=False, through='Match',
                                   related_name='related_to+')

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

  task_id = models.UUIDField(db_index=True, unique=True, editable=False)

  # store matched objects
  created = models.DateTimeField(auto_now_add=True)
  finished = models.DateTimeField(null=True)

  owner = models.ForeignKey(User, db_index=True)
  status = models.CharField(default=STATUS_PENDING, max_length=16,
                            choices=STATUS_CHOICES)

  source_file = models.ForeignKey(File, related_name='source_tasks')
  # TODO: make sure start > end
  source_start = models.PositiveIntegerField(null=True)
  source_end = models.PositiveIntegerField(null=True)
  # TODO: make sure only at least one of target_file/target_project is null
  target_file = models.ForeignKey(File, null=True)
  target_project = models.ForeignKey(Project, null=True)

  progress = models.PositiveSmallIntegerField(default=0)
  progress_max = models.PositiveSmallIntegerField(null=True)


class Match(models.Model):
  from_vector = models.ForeignKey(Vector, related_name='from_vector')
  to_vector = models.ForeignKey(Vector, related_name='to_vector')

  from_instance = models.ForeignKey(Instance, related_name='from_instance')
  to_instance = models.ForeignKey(Instance, related_name='to_instance')

  task = models.ForeignKey(Task, db_index=True, related_name='matches')

  type = models.CharField(max_length=16, choices=Vector.TYPE_CHOICES)
  score = models.FloatField()


#
# Anotations
#

class Annotation(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  modified = models.DateTimeField(auto_now=True)
  owner = models.ForeignKey(User, db_index=True)
  instance = models.ForeignKey(Instance)

  offset = models.IntegerField()


class NameAnnotation(Annotation):
  name = models.CharField(max_length=256)


class CommentAnnotation(Annotation):
  comment = models.TextField()


class RptCommentAnnotation(Annotation):
  comment = models.TextField()


class AboveLineCommentAnnotation(Annotation):
  comment = models.TextField()


class BelowLineCommentAnnotation(Annotation):
  comment = models.TextField()
