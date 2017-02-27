import itertools
import json
import time

import numpy as np
import sklearn as skl
import sklearn.metrics  # noqa flake8 importing as a different name
import sklearn.preprocessing  # noqa flake8 importing as a different name
import sklearn.feature_extraction  # noqa flake8 importing as a different name

from . import match


class HistogramMatch(match.Match):
  @staticmethod
  def match(source, target):
    start = time.time()
    source_values = itertools.izip(*source.values_list('instance_id', 'data'))
    target_values = itertools.izip(*target.values_list('instance_id', 'data'))

    print("izip time: {}".format(time.time() - start))

    source_instance_ids, source_data = source_values
    target_instance_ids, target_data = target_values
    print("split time: {}".format(time.time() - start))

    source_list = [json.loads(d) for d in source_data]
    target_list = [json.loads(d) for d in target_data]
    print("load time: {}".format(time.time() - start))
    print("Source input sample:\t{}".format(source_list[:5]))
    print("Source input sample:\t{}".format(target_list[:5]))

    dictvect = skl.feature_extraction.DictVectorizer()
    source_matrix = dictvect.fit_transform(source_list)
    target_matrix = dictvect.transform(target_list)
    print("vectorization time: {}".format(time.time() - start))
    print("source matrix: {}, target matrix: {}".format(source_matrix.shape,
                                                        target_matrix.shape))

    source_matrix = skl.preprocessing.normalize(source_matrix, norm='l2')
    target_matrix = skl.preprocessing.normalize(target_matrix, norm='l2')
    print("norm time: {}".format(time.time() - start))

    distance_matrix = skl.metrics.pairwise.euclidean_distances(source_matrix,
                                                               target_matrix)
    print("distance time: {}".format(time.time() - start))
    print("min distance: {}, max distance: {}".format(distance_matrix.min(),
                                                      distance_matrix.max()))

    for source_i, target_i in np.ndindex(*distance_matrix.shape):
      source_instance_id = source_instance_ids[source_i]
      target_instance_id = target_instance_ids[target_i]

      distance = distance_matrix[source_i][target_i]
      score = (1 - distance) * 100
      yield (source_instance_id, target_instance_id, score)
