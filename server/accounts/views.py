from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET'])
def profile(request):
  # workaround django 1.10+ being a BoolCallable instead of an actual boolean
  # to stay backwards compatible with earlier versions where this attribute
  # was a method and not a property
  is_authenticated = request.user.is_authenticated
  if callable(is_authenticated):
    is_authenticated = is_authenticated()

  user = {"id": request.user.id,
          "is_authenticated": is_authenticated,
          "is_active": request.user.is_active,
          "is_staff": request.user.is_staff,
          "is_superuser": request.user.is_superuser,
          }
  if is_authenticated:
    user.update({"username": request.user.username,
                 "first_name": request.user.first_name,
                 "last_name": request.user.last_name,
                 "email": request.user.email,
                 })

  return Response(user)
