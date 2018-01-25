import ida_gdl
import ida_funcs
import ida_lines
import idautils

from . import annotation


class CommentAnnotation(annotation.Annotation):
  @staticmethod
  def data(offset):
    func = ida_funcs.get_func(offset)

    comments = [ea - offset: self.get_comment(ea)
                  for ea in idautils.Heads(func.startEA, func.endEA)]
    return comments

  @staticmethod
  def get_comment(self, ea):
    raise NotImplementedError("get_comment method not implemented")


def RegularCommentAnnotation(CommentAnnotation):
  @staticmethod
  def get_comment(ea):
    return ida_bytes.get_cmt(ea, 0)
