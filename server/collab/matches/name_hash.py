from . import hash_match


class NameHashMatch(hash_match.HashMatch):
  vector_type = 'name_hash'
  match_type = 'name_hash'
