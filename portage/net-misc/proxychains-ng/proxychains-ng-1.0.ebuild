# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4
inherit cmake-utils

DESCRIPTION="force any tcp connections to flow through a proxy (or proxy chain)"
SRC_URI="${P}.tar.bz2"
RESTRICT="fetch"
HOMEPAGE=""
KEYWORDS="amd64 ~x86"
SLOT="0"
LICENSE="GPL-2"
IUSE="threads"

RDEPEND="${RDEPEND}
	net-dns/bind-tools"

src_configure()
{
    local mycmakeargs="
        $(cmake-utils_use threads USE_THREADS)
        "
    cmake-utils_src_configure
}
