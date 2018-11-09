from django.forms import ValidationError


def idb_validator(fh):
  magic = fh.read(4)
  if magic not in ("IDA1", "IDA2"):
    raise ValidationError("file is not a valid IDA database (*.IDB) file.")
