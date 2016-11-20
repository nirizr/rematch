from . import hash_match


class MnemonicHashMatch(hash_match.HashMatch):
  vector_type = 'mnemonic_hash'
  match_type = 'mnemonic_hash'
