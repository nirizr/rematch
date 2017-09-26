from .matcher import Matcher
from .hash_matcher import HashMatcher
from .euclidean_matcher import EuclideanDictionaryMatcher
from .identity_hash import IdentityHashMatcher
from .assembly_hash import AssemblyHashMatcher
from .mnemonic_hash import MnemonicHashMatcher
from .name_hash import NameHashMatcher
from .mnemonic_euclidean import MnemonicEuclideanMatcher
from .dictionary_matcher import DictionaryMatcher


matchers_list = [IdentityHashMatcher, NameHashMatcher, AssemblyHashMatcher,
                 MnemonicHashMatcher, MnemonicEuclideanMatcher]

__all__ = ['Matcher', 'HashMatcher', 'EuclideanDictionaryMatcher',
           'IdentityHashMatcher', 'AssemblyHashMatcher', 'MnemonicHashMatcher',
           'NameHashMatcher', 'MnemonicEuclideanMatcher', 'DictionaryMatcher',
           'matchers_list']
