from . import hash_matcher


class IdentityHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'identity_hash'
  match_type = 'identity_hash'
  matcher_name = "Identity Hash"
  matcher_description = ("Exact matches for functions with identical binary "
                         "representation, mostly offset values are ignored.")
