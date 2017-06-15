import itertools
import json

import numpy as np
import sklearn as skl
import sklearn.metrics  # noqa flake8 importing as a different name
import sklearn.preprocessing  # noqa flake8 importing as a different name
import sklearn.feature_extraction  # noqa flake8 importing as a different name

from . import matcher


class HistogramMatcher(matcher.Matcher):
  @staticmethod
  def match(source, target):
    source_values = itertools.izip(*source.values_list('instance_id', 'data'))
    target_values = itertools.izip(*target.values_list('instance_id', 'data'))

    source_instance_ids, source_data = source_values
    target_instance_ids, target_data = target_values

    source_list = [json.loads(d) for d in source_data]
    target_list = [json.loads(d) for d in target_data]

    dictvect = skl.feature_extraction.DictVectorizer()
    source_matrix = dictvect.fit_transform(source_list)
    target_matrix = dictvect.transform(target_list)
    print("source matrix: {}, target matrix: {}".format(source_matrix.shape,
                                                        target_matrix.shape))

    distance_matrix = skl.metrics.pairwise.euclidean_distances(source_matrix,
                                                               target_matrix)
    max_distance = distance_matrix.max()
    score_matrix = (1 - (distance_matrix / max_distance)) * 100
    print("min, max dist: {}, {}".format(distance_matrix.min(), max_distance))

    for source_i, target_i in np.ndindex(*distance_matrix.shape):
      source_instance_id = source_instance_ids[source_i]
      target_instance_id = target_instance_ids[target_i]

      score = score_matrix[source_i][target_i]
      yield (source_instance_id, target_instance_id, score)
