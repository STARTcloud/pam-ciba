#!/usr/bin/bash
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2026 Makr91. All rights reserved.
# Use is subject to license terms.
#

set -e

logmsg() { echo "=== $*"; }
logcmd() { echo ">>> $*"; "$@"; }
logerr() { echo "ERROR: $*" >&2; }

SRCDIR="$(pwd)"
DESTDIR="${SRCDIR}/proto"
PROG=pam-ciba
VER="${VERSION:-$(sed -n 's/.*Version = "\([^"]*\)".*/\1/p' internal/version/version.go)}"
PKG=system/security/pam-ciba

rm -rf "$DESTDIR"
mkdir -p "$DESTDIR"

build_app() {
    logmsg "Building PAM CIBA"
    export CGO_ENABLED=0
    logcmd go build -trimpath -ldflags "-s -w -X github.com/STARTcloud/pam-ciba/internal/version.Version=${VER}" -o "${PROG}" .

    logmsg "Building the PAM service module"
    logcmd gcc -m64 -shared -fPIC -Wall -o pam_ciba.so.1 packaging/omnios/pam_ciba.c -lpam
}

install_app() {
    pushd $DESTDIR >/dev/null

    logcmd mkdir -p opt/pam-ciba
    pushd opt/pam-ciba >/dev/null

    logmsg "Installing PAM CIBA application files"
    logcmd cp $SRCDIR/${PROG} .
    logcmd cp $SRCDIR/LICENSE.md .

    popd >/dev/null

    logmsg "Installing the PAM service module"
    logcmd mkdir -p usr/lib/security/amd64
    logcmd cp $SRCDIR/pam_ciba.so.1 usr/lib/security/amd64/pam_ciba.so.1

    logmsg "Installing configuration files"
    logcmd mkdir -p etc/pam-ciba
    logcmd cp $SRCDIR/internal/config/seed/app.config.yaml etc/pam-ciba/app.config.yaml

    logmsg "Installing man pages"
    logcmd mkdir -p opt/ooce/share/man/man8 opt/ooce/share/man/man5
    logcmd cp $SRCDIR/packaging/DEBIAN/man/pam-ciba.8 opt/ooce/share/man/man8/ ||         logerr "--- copying main man page failed"
    logcmd cp $SRCDIR/packaging/DEBIAN/man/pam-ciba.yaml.5 opt/ooce/share/man/man5/ ||         logerr "--- copying config man page failed"

    popd >/dev/null
}

logmsg "Starting PAM CIBA build process"
build_app
install_app

logmsg "Creating IPS package"
cd "$SRCDIR"
export VERSION="$VER"
sed "s/@VERSION@/${VERSION}/g" packaging/omnios/pam-ciba.p5m > pam-ciba.p5m.tmp
pkgsend generate proto | pkgfmt > pam-ciba.p5m.generated
pkgmogrify -DVERSION="${VERSION}" pam-ciba.p5m.tmp pam-ciba.p5m.generated > pam-ciba.p5m.final

TEMP_REPO="${SRCDIR}/temp-repo"
rm -rf "$TEMP_REPO"
pkgrepo create "$TEMP_REPO"
pkgrepo set -s "$TEMP_REPO" publisher/prefix=Makr91

pkgsend -s "file://${TEMP_REPO}" publish -d proto pam-ciba.p5m.final

PACKAGE_FILE="pam-ciba-${VERSION}.p5p"
pkgrecv -s "file://${TEMP_REPO}" -a -d "${PACKAGE_FILE}" "${PKG}"

rm -rf "$TEMP_REPO"

logmsg "Package build completed: ${PACKAGE_FILE}"
logmsg "Complete package ready for upload to GitHub artifacts"

# Vim hints
# vim:ts=4:sw=4:et:
