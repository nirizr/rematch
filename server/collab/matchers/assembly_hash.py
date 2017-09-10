from . import hash_matcher


class AssemblyHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'assembly_hash'
  match_type = 'assembly_hash'
  matcher_name = "Assembly Hash"
  matcher_description = ("Exact matches for functions with identical assembly "
                         "listings.")
