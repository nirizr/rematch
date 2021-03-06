from itertools import islice, chain

from collab.models import Task, Vector, Match
from collab import strategies

from celery import shared_task

from django.utils.timezone import now
from django.db.models import F

import numpy as np


@shared_task
def match(task_id):
  try:
    task = Task.objects.filter(id=task_id)

    # get input parameters
    task_values = task.values('source_start', 'source_end', 'target_file',
                              'target_project', 'source_file_version',
                              'matchers', 'strategy',
                              source_file=F('source_file_version__file')).get()

    # create strategy instance
    strategy = strategies.get_strategy(vector_cls=Vector, **task_values)

    # building steps according to strategy
    steps = strategy.get_ordered_steps()

    # recording the task has started
    task.update(status=Task.STATUS_STARTED, task_id=match.request.id,
                progress_max=len(steps), progress=0)

    local_ids = set()
    remote_ids = set()
    print("Running task {}, strategy {}".format(match.request.id, strategy))
    # TODO: local and remote counts are wrong, they count all vectors used
    # instead of number of vectors that actually matched
    for step in steps:
      match_count = match_by_step(task_id, local_ids, remote_ids, step)
      task.update(progress=F('progress') + 1,
                  match_count=F('match_count') + match_count,
                  local_count=len(local_ids), remote_count=len(remote_ids))

    # sanity checks
    if not task.filter(progress=F('progress_max')).count():
      raise RuntimeError("Task successfully finished without executing all "
                         "steps")

    match_count = Match.objects.filter(task_id=task_id).count()
    if not task.filter(match_count=match_count).count():
        raise RuntimeError("Collected counts of matches does not match final "
                           "matches count")
  except Exception:
    task.update(status=Task.STATUS_FAILED, finished=now())
    raise

  task.update(status=Task.STATUS_DONE, finished=now())


# Django bulk_create converts `objs` to a list, rendering any generator
# useless. This batch method is used to implement `batch_size` functionality
# outside of `bulk_create`.
# For more info and status see:
# https://code.djangoproject.com/ticket/28231
def batch(iterable, size):
    sourceiter = iter(iterable)
    while True:
        batchiter = islice(sourceiter, size)
        yield chain([next(batchiter)], batchiter)
    return


def match_by_step(task_id, local_ids, remote_ids, step):
  start = now()
  source_vectors = Vector.objects.filter(step.get_source_filter())
  target_vectors = Vector.objects.filter(step.get_target_filter())

  local_count = source_vectors.count()
  remote_count = target_vectors.count()
  if not local_count or not remote_count:
    print("Skipped step {} with {} local vectors and {} remote vectors"
          "".format(step, local_count, remote_count))
    return 0

  print("Matching {} local vectors to {} remote vectors by {}"
        "".format(local_count, remote_count, step))

  match_count = 0
  match_objs = gen_match_objs(task_id, step, source_vectors, target_vectors,
                              local_ids, remote_ids)
  for b in batch(match_objs, 10000):
    # bulk_create turns b into a list regardless, so lets make it useful
    b = list(b)
    match_count += len(b)
    Match.objects.bulk_create(b)
  print("Took {} and resulted in {} match objects".format(now() - start,
                                                          match_count))

  return match_count


def gen_match_objs(task_id, step, source_vectors, target_vectors, local_ids,
                   remote_ids):
  matches = step.gen_matches(source_vectors, target_vectors)
  for source_instance, target_instance, score in matches:
    if not np.isfinite(score):
      print("Infinite score detected: {} in step {} between {} and {}"
            "".format(score, step, source_instance, target_instance))
      continue
    if score < 50:
      continue
    mat = Match(task_id=task_id, from_instance_id=source_instance,
                to_instance_id=target_instance, score=score,
                type=step.get_match_type())
    local_ids.add(source_instance)
    remote_ids.add(target_instance)
    yield mat
