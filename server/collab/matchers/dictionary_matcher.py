import itertools
import json

import numpy as np
import sklearn as skl
import sklearn.metrics  # noqa flake8 importing as a different name
import sklearn.feature_extraction  # noqa flake8 importing as a different name

from . import matcher


class DictionaryMatcher(matcher.Matcher):
  @classmethod
  def format_data(cls, source, target):
    source_rows = itertools.izip(*source.values_list('instance_id', 'data'))
    target_rows = itertools.izip(*target.values_list('instance_id', 'data'))

    source_instance_ids, source_json = source_rows
    target_instance_ids, target_json = target_rows

    source_data = [json.loads(d) for d in source_json]
    target_data = [json.loads(d) for d in target_json]

    source_values = source_instance_ids, source_data
    target_values = target_instance_ids, target_data

    return source_values, target_values

  @classmethod
  def match(cls, source, target):
    source_values, target_values = cls.format_data(source, target)
    source_instance_ids, source_data = source_values
    target_instance_ids, target_data = target_values

    dictvect = skl.feature_extraction.DictVectorizer()
    source_matrix = dictvect.fit(source_data + target_data)
    source_matrix = dictvect.transform(source_data)
    target_matrix = dictvect.transform(target_data)
    print("source matrix: {}, target matrix: {}".format(source_matrix.shape,
                                                        target_matrix.shape))

    distance_matrix = cls.cmp_fn(source_matrix, target_matrix)
    print("min, max dist: {}, {}".format(distance_matrix.min(),
                                         distance_matrix.max()))

    distance_matrix = (1 - (distance_matrix / distance_matrix.max())) * 100
    for source_i, target_i in np.ndindex(*distance_matrix.shape):
      yield (source_instance_ids[source_i],
             target_instance_ids[target_i],
             distance_matrix[source_i][target_i])
