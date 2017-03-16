import idaplugin


def test_main(idapro_app):
  del idapro_app

  idaplugin.rematch.autoupload.main()
