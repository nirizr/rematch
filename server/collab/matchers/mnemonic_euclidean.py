from django.db.models import Q


from . import euclidean_matcher


class MnemonicEuclideanMatcher(euclidean_matcher.EuclideanDictionaryMatcher):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_euclidean'
  matcher_name = "Mnemonic Euclidean Distance"
  matcher_description = ("Matches functions according to their mnemonic "
                         "listing using histogram and an euclidean distance "
                         "metric.")

  @staticmethod
  def get_filter():
    return Q(instance__count__gte=10)
