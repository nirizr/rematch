from django.forms import ValidationError


def idb_validator(fh):
  magic = fh.read(4)
  if magic not in ("IDA1", "IDA2"):
    raise ValidationError("file magic is not a valid IDA database (*.IDB) "
                          "magic: '{}'.".format(magic))
