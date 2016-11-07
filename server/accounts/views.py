from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET'])
def profile(request):
  user = {"id": request.user.id,
          "is_authenticated": request.user.is_authenticated(),
          "is_active": request.user.is_active,
          "is_staff": request.user.is_staff,
          "is_superuser": request.user.is_superuser,
          }
  if request.user.is_authenticated():
    user.update({"username": request.user.username,
                 "first_name": request.user.first_name,
                 "last_name": request.user.last_name,
                 "email": request.user.email,
                 })
  return Response(user, template_name='profile.html')
