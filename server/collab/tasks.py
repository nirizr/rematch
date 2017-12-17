from django.utils.timezone import now
from django.db.models import F
from collab.models import Task, Vector, Match
from collab import strategies

from celery import shared_task

from itertools import islice, chain


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
    strategy = strategies.get_strategy(**task_values)

    # build vector objects from strategy filters
    source_vectors = Vector.objects.filter(strategy.get_source_filters())
    target_vectors = Vector.objects.filter(strategy.get_target_filters())

    # building steps according to strategy
    steps = strategy.get_ordered_steps(source_vectors, target_vectors)

    # recording the task has started
    task.update(status=Task.STATUS_STARTED, task_id=match.request.id,
                progress_max=len(steps), progress=0)

    print("Running task {}, strategy {}".format(match.request.id, strategy))
    for step in steps:
      match_by_step(task_id, step, source_vectors, target_vectors)
      task.update(progress=F('progress') + 1)
  except Exception:
    task.update(status=Task.STATUS_FAILED, finished=now())
    raise

  if not task.filter(progress=F('progress_max')).count():
    raise RuntimeError("Task successfully finished without executing all "
                       "steps")

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
        yield chain([batchiter.next()], batchiter)


def match_by_step(task_id, step, source_vectors, target_vectors):
  start = now()
  source_vectors = source_vectors.filter(step.get_source_filters())
  target_vectors = target_vectors.filter(step.get_target_filters())

  source_count = source_vectors.count()
  target_count = target_vectors.count()
  if not source_count or not target_count:
    print("Skipped step {} with {} local vectors and {} remote vectors"
          "".format(step, source_count, target_count))
    return

  print("Matching {} local vectors to {} remote vectors by {}"
        "".format(source_count, target_count, step))

  match_objs = gen_match_objs(task_id, step, source_vectors, target_vectors)
  for b in batch(match_objs, 10000):
    Match.objects.bulk_create(b)
  matches_count = Match.objects.filter(task_id=task_id)
  matches_count = matches_count.filter(step.get_results_filter()).count()
  print("Took {} and resulted in {} match objects".format(now() - start,
                                                          matches_count))


def gen_match_objs(task_id, step, source_vectors, target_vectors):
  matches = step.gen_matches(source_vectors, target_vectors)
  for source_instance, target_instance, score in matches:
    if score < 50:
      continue
    mat = Match(task_id=task_id, from_instance_id=source_instance,
                to_instance_id=target_instance, score=score,
                type=step.get_match_type())
    yield mat
