from collab.models import (Project, File, FileVersion, Task, Instance, Vector,
                           Annotation)
from django.contrib import admin

admin.site.register(Project)
admin.site.register(File)
admin.site.register(FileVersion)
admin.site.register(Task)
admin.site.register(Instance)
admin.site.register(Vector)
admin.site.register(Annotation)
