from . import hist_match


class MnemonicHistogramMatch(hist_match.HistogramMatch):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_hist'
