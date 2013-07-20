# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4
inherit cmake-utils

DESCRIPTION="Fork of proxychains with support of multiple chains. Chains are selected according to filters assigned to them."
SRC_URI="${P}.tar.bz2"
HOMEPAGE="https://github.com/oleg-liatte/proxychains-multi"
KEYWORDS="amd64 ~x86"
SLOT="0"
LICENSE="GPL-2"
IUSE="threads"

RDEPEND+="
    net-dns/bind-tools"

DEPEND+="
    sys-devel/flex
    sys-devel/bison"

src_configure()
{
    local mycmakeargs="
        $(cmake-utils_use threads USE_THREADS)
        "
    cmake-utils_src_configure
}
