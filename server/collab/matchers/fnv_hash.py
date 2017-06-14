from . import hash_matcher


class FnvHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'fnv_hash'
  match_type = 'fnv_hash'
  matcher_name = 'FNV Hash'
