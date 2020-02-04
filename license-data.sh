#!/usr/bin/env bash

VENDOR_DIR=vendor/choosealicense.com
rm -Rf $VENDOR_DIR
mkdir -p $VENDOR_DIR
[[ $(tar --version | head -n 1) =~ bsdtar.* ]] || taropt='--wildcards'
curl -L https://api.github.com/repos/github/choosealicense.com/tarball |tar zxf - -C $VENDOR_DIR $taropt --strip-components=1 */_data/* */_licenses/*

