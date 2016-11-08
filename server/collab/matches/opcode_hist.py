import hist_match


class OpcodeHistogramMatch(hist_match.HistogramMatch):
  vector_type = 'opcode_histogram'
  match_type = 'opcode_histogram'
