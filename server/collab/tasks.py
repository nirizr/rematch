from django.utils.timezone import now
from django.db.models import F
from collab.models import Task, Vector, Match
from collab.matchers import matchers_list

from celery import shared_task

import json

from itertools import islice, chain


@shared_task
def match(task_id):
  try:
    task = Task.objects.filter(id=task_id)

    # get input parameters
    task_values = task.values_list('source_file_version__file_id',
                                   'source_start', 'source_end',
                                   'source_file_version_id',
                                   'target_project_id', 'target_file_id',
                                   'matchers').get()
    print(task_values)
    (source_vectors, target_vectors, matchers) = build_filters(*task_values)

    # recording the task has started
    task.update(status=Task.STATUS_STARTED, progress=0,
                progress_max=len(matchers), task_id=match.request.id)

    print("Running task {}".format(match.request.id))
    # TODO: order might be important here
    for matcher in matchers_list:
      if matcher.match_type not in matchers:
        continue
      matchers.remove(matcher.match_type)

      match_by_matcher(task_id, matcher, source_vectors, target_vectors)

      task.update(progress=F('progress') + 1)

    if matchers:
      msg = "Unfamiliar matchers were requested: {}".format(matchers)
      raise ValueError(msg)
  except Exception:
    task.update(status=Task.STATUS_FAILED, finished=now())
    raise

  task.update(status=Task.STATUS_DONE, finished=now())


def build_filters(source_file, source_start, source_end, source_file_version,
                  target_project, target_file, matchers):
  source_filter = {'file_version__file': source_file,
                   'file_version_id': source_file_version}
  if source_start:
    source_filter['instance__offset__gte'] = source_start
  if source_end:
    source_filter['instance__offset__lte'] = source_end
  source_vectors = Vector.objects.filter(**source_filter)

  target_filter = {}
  if target_project:
    target_filter = {'file_version__file__project_id': target_project}
  elif target_file:
    target_filter = {'file_version__file': target_file}
  target_vectors = Vector.objects.filter(**target_filter)
  self_exclude = {'file_version__file': source_file}
  target_vectors = target_vectors.exclude(**self_exclude)

  matchers = set(json.loads(matchers))

  return (source_vectors, target_vectors, matchers)


# Django bulk_create converts `objs` to a list, rendering any generator
# useless. This batch method is used to implement `batch_size` functionality
# outside of `bulk_create`.
# For more info and status see:
# https://code.djangoproject.com/ticket/28231
def batch(iterable, size):
    sourceiter = iter(iterable)
    while True:
        batchiter = islice(sourceiter, size)
        yield chain([batchiter.next()], batchiter)


def match_by_matcher(task_id, matcher, source_vectors, target_vectors):
  start = now()
  source_vectors = source_vectors.filter(type=matcher.vector_type)
  target_vectors = target_vectors.filter(type=matcher.vector_type)

  source_count = source_vectors.count()
  target_count = target_vectors.count()
  if source_count and target_count:
    print("Matching {} local vectors to {} remote vectors by {}"
          "".format(source_count, target_count, matcher))
    match_objs = gen_match_objs(task_id, matcher, source_vectors,
                                target_vectors)
    for b in batch(match_objs, 10000):
      Match.objects.bulk_create(b)
    matches = Match.objects.filter(task_id=task_id,
                                   type=matcher.match_type).count()
    print("Resulted in {} match objects".format(matches))
  else:
    print("Skipped matcher {} with {} local vectors and {} remote vectors"
          "".format(matcher, source_count, target_count))
  print("\tTook: {}".format(now() - start))


def gen_match_objs(task_id, matcher, source_vectors, target_vectors):
  matches = matcher.match(source_vectors, target_vectors)
  for source_instance, target_instance, score in matches:
    if score < 50:
      continue
    mat = Match(task_id=task_id, from_instance_id=source_instance,
                to_instance_id=target_instance, score=score,
                type=matcher.match_type)
    yield mat
