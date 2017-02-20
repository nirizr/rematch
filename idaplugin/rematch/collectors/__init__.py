from .collector import Collector
from .vector import Vector
from .name_hash import NameHashVector
from .assembly_hash import AssemblyHashVector
from .mnemonic_hash import MnemonicHashVector
from .mnemonic_hist import MnemonicHistVector
from .annotation import Annotation
from .name_annotation import NameAnnotation
from .assembly_annotation import AssemblyAnnotation
from .prototype_annotation import PrototypeAnnotation


def collect(offset, collectors):
  for collector in collectors:
    c = collector(offset)
    if c.include():
      yield c.serialize()


__all__ = ["collect", "Collector", "Vector", "NameHashVector",
           "AssemblyHashVector", "MnemonicHashVector", "MnemonicHistVector",
           "Annotation", "NameAnnotation", "AssemblyAnnotation",
           "PrototypeAnnotation"]
