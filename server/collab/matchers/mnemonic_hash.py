from django.db.models import Q


from . import hash_matcher


class MnemonicHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'mnemonic_hash'
  match_type = 'mnemonic_hash'
  matcher_name = "Mnemonic Hash"
  matcher_description = ("Exact matches for functions with identical mnemonic "
                         "listings.")

  @staticmethod
  def get_filter():
    return Q(instance__count__gte=10)
