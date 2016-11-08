from collab.models import (Project, File, Task, Instance, Vector,
                           NameAnnotation, CommentAnnotation,
                           RptCommentAnnotation, AboveLineCommentAnnotation,
                           BelowLineCommentAnnotation)
from django.contrib import admin

admin.site.register(Project)
admin.site.register(File)
admin.site.register(Task)
admin.site.register(Instance)
admin.site.register(Vector)

# TODO: add in a different list
admin.site.register(NameAnnotation)
admin.site.register(CommentAnnotation)
admin.site.register(RptCommentAnnotation)
admin.site.register(AboveLineCommentAnnotation)
admin.site.register(BelowLineCommentAnnotation)
