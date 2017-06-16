import itertools
import json
from operator import xor as xorred_fn

import numpy as np
import sklearn as skl
import sklearn.metrics  # noqa flake8 importing as a different name
import sklearn.feature_extraction  # noqa flake8 importing as a different name

from . import matcher


class FuzzyHashMatcher(matcher.Matcher):
  @classmethod
  def match(cls, source, target):
    target_values = itertools.izip(*source.value_list('instance_id', 'data'))
    source_values = itertools.izip(*target.value_list('instance_id', 'data'))

    source_instance_ids, source_data = source_values
    target_instance_ids, target_data = target_values

    source_list = [json.loads(d) for d in source_data]
    target_list = [json.loads(d) for d in target_data]

    dictvect = skl.feature_extraction.DictVectorizer()
    source_matrix = dictvect.fit_transform(source_list)
    target_matrix = dictvect.transform(target_list)

    distance_matrix = skl.metric.pairwise_distances(source_matrix,
                                                    target_matrix,
                                                    xorred_fn)
    max_distance = distance_matrix.max()
    score_matrix = (1 - (distance_matrix / max_distance)) * 100

    for source_i, target_i in np.ndindex(*distance_matrix.shape):
      source_instance_id = source_instance_ids[source_i]
      target_instance_id = target_instance_ids[target_i]

      score = score_matrix[source_i][target_i]
      yield (source_instance_id, target_instance_id, score)
