# Reproducibility copy of the v850-elf cross toolchain used for the deep-probe
# shellcode (gcc 13.2.0 + binutils 2.41 on ubuntu 22.04). Not used for the
# routine build: the build runs in the homelab docker image
# `gcc-v850-elf-master:latest`, which was produced from a script equivalent to
# this Dockerfile.

FROM ubuntu:22.04

ENV TARGET_ARCH="v850-elf"
ENV TOOLCHAIN_VERSION="master"
ENV TOOLCHAIN_NAME="gcc-${TARGET_ARCH}-${TOOLCHAIN_VERSION}"
ENV TOOLCHAIN_PATH="/opt/${TOOLCHAIN_NAME}"
ENV PATH="${TOOLCHAIN_PATH}/bin:${PATH}"

RUN apt-get update && apt-get install -y build-essential bison flex libgmp3-dev libmpc-dev libmpfr-dev texinfo git

WORKDIR /src
RUN git clone --depth=1 --branch=binutils-2_41-release git://sourceware.org/git/binutils-gdb.git

# Build binutils
WORKDIR /build/binutils
RUN /src/binutils-gdb/configure \
        --target=${TARGET_ARCH} \
        --prefix=${TOOLCHAIN_PATH} \
        --disable-nls
RUN  make -j$(nproc) all
RUN  make install

# Build gcc
WORKDIR /src
RUN git clone --depth=1 --branch=releases/gcc-13.2.0 git://gcc.gnu.org/git/gcc.git

WORKDIR /build/gcc

RUN /src/gcc/configure \
        --target=${TARGET_ARCH} \
        --prefix=${TOOLCHAIN_PATH} \
        --disable-nls \
        --enable-languages=c \
        --without-headers \
        --with-gnu-as \
        --with-gnu-ld \
        --disable-shared \
        --disable-libssp \
        --disable-threads \
        --disable-nls \
        --with-newlib

RUN make -j$(nproc) all-gcc
RUN make install-gcc

WORKDIR /src
