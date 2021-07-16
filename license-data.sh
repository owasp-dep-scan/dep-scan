#!/usr/bin/env bash

VENDOR_DIR=vendor/choosealicense.com
SPDX_VENDOR_DIR=vendor/spdx
rm -Rf $VENDOR_DIR $SPDX_VENDOR_DIR
mkdir -p $VENDOR_DIR $SPDX_VENDOR_DIR
[[ $(tar --version | head -n 1) =~ bsdtar.* ]] || taropt='--wildcards'
curl -L https://api.github.com/repos/github/choosealicense.com/tarball |tar zxf - -C $VENDOR_DIR $taropt --strip-components=1 */_data/* */_licenses/*

curl -L https://api.github.com/repos/spdx/license-list-data/tarball |tar zxf - -C $SPDX_VENDOR_DIR $taropt --strip-components=1 */json/licenses.json*
