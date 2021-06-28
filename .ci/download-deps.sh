#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {

	export TSS_VERSION=${TPM2_TSS_VERSION:-3.0.2}
	ABRMD_VERSION=2.3.3
	EXTRA_CONFIG_FLAGS=''

	pkg_conf_path="$(pkg-config --variable pc_path pkg-config | cut -d: -f 1-1)"
	if [ "$pkg_conf_path" != "/usr/lib/pkgconfig" ]; then
		echo "Detected non-standard pkgconfig path: \"$pkg_conf_path\""
		EXTRA_CONFIG_FLAGS="--with-pkgconfigdir=\"$pkg_conf_path\""
	fi

	echo "pwd starting: `pwd`"
	if [ "$TSS_VERSION" = "2.4.0" ]; then
		if [ "$DOCKER_IMAGE" = "fedora-30" ]; then
			yum -y install libgcrypt-devel
		elif [ "$DOCKER_IMAGE" = "opensuse-leap" ]; then
			zypper -n in libgcrypt-devel
		elif [ "$DOCKER_IMAGE" = "ubuntu-20.04" -o "$DOCKER_IMAGE" = "ubuntu-18.04" ]; then
			apt-get -y install libgcrypt20-dev
		fi
	fi
	pushd "$1"
	echo "pwd clone tss: `pwd`"
	if [ ! -d tpm2-tss ]; then
		if [ -z "$GIT_FULL_CLONE" ]; then
			echo "Doing shallow clone of tss"
			git_extra_flags="--depth=1"
		else
			echo "Doing deep clone of tss"
		fi
		git clone $git_extra_flags \
		--branch "$TSS_VERSION" https://github.com/tpm2-software/tpm2-tss.git
		pushd tpm2-tss
		echo "pwd build tss: `pwd`"
		./bootstrap
		./configure --disable-doxygen-doc $EXTRA_CONFIG_FLAGS CFLAGS=-g
		make -j4
		make install
		popd
		echo "pwd done tss: `pwd`"
	else
		echo "tss already downloaded/built/installed, skipping"
	fi

	if [ ! -d tpm2-abrmd ]; then
		echo "pwd clone abrmd: `pwd`"
		git clone --depth=1 \
		--branch "$ABRMD_VERSION" https://github.com/tpm2-software/tpm2-abrmd.git
		pushd tpm2-abrmd
		echo "pwd build abrmd: `pwd`"
		./bootstrap
		./configure $EXTRA_CONFIG_FLAGS CFLAGS=-g
		make -j4
		make install
		popd
		echo "pwd done abrmd: `pwd`"
		popd
		echo "pwd done: `pwd`"
	else
		echo "abrmd already downloaded/built/installed, skipping"
	fi

}
