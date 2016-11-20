from .assembly_hash import AssemblyHashMatch
from .mnemonic_hash import MnemonicHashMatch
from .mnemonic_hist import MnemonicHistogramMatch
from .opcode_hist import OpcodeHistogramMatch


match_list = [AssemblyHashMatch, MnemonicHashMatch, MnemonicHistogramMatch,
              OpcodeHistogramMatch]

__all__ = ['AssemblyHashMatch', 'MnemonicHashMatch', 'MnemonicHistogramMatch',
           'OpcodeHistogramMatch', 'match_list']
