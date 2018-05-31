import ida_funcs
import ida_bytes
import idautils

from . import annotation


class CommentAnnotation(annotation.Annotation):
  def data(self):
    func = ida_funcs.get_func(self.offset)

    comments = {ea - self.offset: self.get_comment(ea)
                  for ea in idautils.Heads(func.startEA, func.endEA)}
    return comments

  def get_comment(self, ea):
    raise NotImplementedError("get_comment method not implemented")


class RegularCommentAnnotation(CommentAnnotation):
  @staticmethod
  def get_comment(ea):
    return ida_bytes.get_cmt(ea, 0)
