from .identity_hash import IdentityHashMatcher
from .assembly_hash import AssemblyHashMatcher
from .mnemonic_hash import MnemonicHashMatcher
from .name_hash import NameHashMatcher
from .mnemonic_hist import MnemonicHistogramMatcher


matchers_list = [IdentityHashMatcher, NameHashMatcher, AssemblyHashMatcher,
                 MnemonicHashMatcher, MnemonicHistogramMatcher]

__all__ = ['IdentityHashMatcher', 'AssemblyHashMatcher', 'MnemonicHashMatcher',
           'NameHashMatcher', 'MnemonicHistogramMatcher', 'matchers_list']
