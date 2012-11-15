# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4
inherit cmake-utils git-2

DESCRIPTION="Fork of proxychains with support of multiple chains. Chains are selected according to filters assigned to them."
SRC_URI=""
HOMEPAGE="https://github.com/oleg-liatte/proxychains-ng"
KEYWORDS="~amd64 ~x86"
SLOT="0"
LICENSE="GPL-2"
IUSE="threads"

RDEPEND+="
    net-dns/bind-tools"

DEPEND+="
    sys-devel/flex
    sys-devel/bison"

EGIT_REPO_URI="git://github.com/oleg-liatte/proxychains-ng.git https://github.com/oleg-liatte/proxychains-ng.git"

src_configure()
{
    local mycmakeargs="
        $(cmake-utils_use threads USE_THREADS)
        "
    cmake-utils_src_configure
}
