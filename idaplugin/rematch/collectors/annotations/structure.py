import idaapi
import ida_struct
import ida_typeinf
import ida_nalt

from . import annotation


class StructureAnnotation(annotation.DependencyAnnotation):
  type = 'structure'

  def __init__(self, idx, *args, **kwargs):
    self.idx = idx
    super(StructureAnnotation, self).__init__(offset=None, *args, **kwargs)

  def dependency_name(self):
    struc_id = ida_struct.get_struc_by_idx(self.idx)
    return ida_struct.get_struc_name(struc_id)

  def data(self):
    # if idx is None this is called for the pre-apply data identity validation
    # we'll return None so data will definitely not match
    if self.idx is None:
      return None

    struc_id = ida_struct.get_struc_by_idx(self.idx)
    struct = ida_struct.get_struc(struc_id)

    # Skip TIL structures
    if struct.from_til():
      return None

    # Skip empty structures
    if not struct.memqty:
      return None

    d = {}
    d['name'] = ida_struct.get_struc_name(struc_id)
    d['comment'] = ida_struct.get_struc_cmt(struc_id, False)
    d['repeatable_comment'] = ida_struct.get_struc_cmt(struc_id, False)
    d['size'] = ida_struct.get_struc_size(struct)
    d['union'] = ida_struct.is_union(struc_id)
    # TODO: struct alignment, hidden, listed

    d['members'] = {}
    member_idx = 0
    while member_idx != idaapi.BADADDR:
        member = struct.get_member(member_idx)
        d['members'][member_idx] = self.member_data(member)
        member_idx = ida_struct.get_next_member_idx(struct, member.soff)
        # TODO: FIX issue with looping over members
        member_idx = idaapi.BADADDR

    return d

  def member_data(self, member):
    d = {}
    # TODO: variable size bool
    # TODO: retrieve_member_info - get operand type member info
    d['name'] = ida_struct.get_member_name(member.id)
    d['size'] = ida_struct.get_member_size(member)
    d['flag'] = member.flag
    d['offset'] = member.soff
    d['comment'] = ida_struct.get_member_cmt(member.id, False)
    d['repeatable_comment'] = ida_struct.get_member_cmt(member.id, True)

    if member.has_ti():
      tinfo = ida_typeinf.tinfo_t()
      ida_struct.get_member_tinfo(tinfo, member)
      d['type_info_serialize'] = tinfo.serialize()
      d['type_info'] = str(tinfo)

    oi = ida_nalt.opinfo_t()
    ida_struct.retrieve_member_info(oi, member)
    # TODO: Do things with OI

    sptr = ida_struct.get_sptr(member)
    if sptr:
      struct_name = ida_struct.get_struc_name(sptr.id)
      d['struct_name'] = struct_name
      d['struct_uuid'] = StructureAnnotation.depend(self, struct_name)
    return d

  @classmethod
  def apply(cls, data):
    struct_id = ida_struct.add_struc(idaapi.BADADDR, data['name'],
                                     data['union'])
    if 'comment' in data and data['comment']:
      ida_struct.set_struc_cmt(struct_id, data['comment'], False)
    if 'repeatable_comment' in data and data['comment']:
      ida_struct.set_struc_cmt(struct_id, data['repeatable_comment'], True)

    if 'members' in data and data['members']:
      struct = ida_struct.get_struc(struct_id)
      for member_idx, member_data in data['members']:
        cls.apply_member(struct, member_data)

  @classmethod
  def apply_member(cls, struct, data):
    ida_struct.add_struc_member(struct, data['name'], data['offset'],
                                data['flag'], data['opinfo'], data['size'])
    member = ida_struct.get_member(struct, data['offset'])
    if 'comment' in data and data['comment']:
      ida_struct.set_member_cmt(member, data['comment'], False)
    if 'repeatable_comment' in data and data['repeatable_comment']:
      ida_struct.set_member_cmt(member, data['repeatable_comment'], True)

    # TODO: properly apply tinfo, opinfo, struct info
