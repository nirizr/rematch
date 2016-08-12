from django.forms import ValidationError


def IdbValidator(fh):
  if not fh.read(4) == "IDA1":
    raise ValidationError("file is not a valid IDA database (*.IDB) file.")
