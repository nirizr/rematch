from . import hash_matcher


class IdentityHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'identity_hash'
  match_type = 'identity_hash'
