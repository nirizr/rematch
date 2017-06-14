from . import hash_matcher


class ApiDominatorMatcher(hash_matcher.HashMatcher):
  vector_type = 'apidom_hash'
  match_type = 'apidom_hash'
  matcher_name = 'API Call Dominator Hash'
