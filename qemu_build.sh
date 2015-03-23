#!/bin/bash

# if you don't have ubuntu you are on your own here
if [ $(which apt-get) ]; then
  echo "fetching qemu build-deps, enter your password"
  sudo apt-get update -qq
  sudo apt-get --no-install-recommends -qq -y build-dep qemu
  sudo apt-get install -qq -y wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
else
  echo "WARNING: you don't have apt-get, you are required to fetch the build deps of QEMU on your own"
fi

# ok, strict mode
set -e

# get qemu if we don't have it
if [ ! -d qemu/qemu-latest ]; then
  rm -rf qemu
  mkdir -p qemu
  cd qemu
  wget http://wiki.qemu-project.org/download/qemu-2.1.0-rc0.tar.bz2
  tar xf qemu-2.1.0-rc0.tar.bz2
  ln -s qemu-2.1.0-rc0 qemu-latest

  ln -s qemu-latest/arm-linux-user/qemu-arm qira-arm
  ln -s qemu-latest/i386-linux-user/qemu-i386 qira-i386
  ln -s qemu-latest/x86_64-linux-user/qemu-x86_64 qira-x86_64
  ln -s qemu-latest/ppc-linux-user/qemu-ppc qira-ppc
  ln -s qemu-latest/aarch64-linux-user/qemu-aarch64 qira-aarch64
  ln -s qemu-latest/mips-linux-user/qemu-mips qira-mips

  cd qemu-latest
  mv tci.c tci.c.bak
  mv disas.c disas.c.bak
  mv linux-user/qemu.h linux-user/qemu.h.bak
  mv linux-user/main.c linux-user/main.c.bak
  mv linux-user/strace.c linux-user/strace.c.bak
  mv linux-user/strace.list linux-user/strace.list.bak
  cd ../../
fi

cd qemu/qemu-latest
ln -sf ../../qemu_mods/tci.c tci.c
ln -sf ../../qemu_mods/disas.c disas.c
ln -sf ../../../qemu_mods/qemu.h linux-user/qemu.h
ln -sf ../../../qemu_mods/main.c linux-user/main.c
ln -sf ../../../qemu_mods/strace.c linux-user/strace.c
ln -sf ../../../qemu_mods/strace.list linux-user/strace.list
./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,ppc-linux-user,aarch64-linux-user,mips-linux-user --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown
make -j $(grep processor < /proc/cpuinfo | wc -l)

