#!/bin/sh

echo "Publishing the IDAPLUGIN package"
REMATCH_SETUP_PACKAGE=idaplugin fullrelease -v

echo "Publishing the SERVER package"
REMATCH_SETUP_PACKAGE=server fullrelease -v
