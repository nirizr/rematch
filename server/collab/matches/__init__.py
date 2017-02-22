from .assembly_hash import AssemblyHashMatch
from .mnemonic_hash import MnemonicHashMatch
from .name_hash import NameHashMatch
from .mnemonic_hist import MnemonicHistogramMatch


match_list = [NameHashMatch, AssemblyHashMatch, MnemonicHashMatch,
              MnemonicHistogramMatch]

__all__ = ['AssemblyHashMatch', 'MnemonicHashMatch', 'NameHashMatch',
           'MnemonicHistogramMatch', 'match_list']
