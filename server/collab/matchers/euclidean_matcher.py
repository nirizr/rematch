from . import dictionary_matcher
from sklearn.metrics.pairwise import euclidean_distances


class EuclideanDictionaryMatcher(dictionary_matcher.DictionaryMatcher):
  @staticmethod
  def cmp_fn(source, target):
    return euclidean_distances(source, target)
