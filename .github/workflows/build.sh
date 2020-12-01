#!/bin/sh

mv ./bin/wrtbwmon ./package/
make defconfig
make package/wrtbwmon/compile V=s -j$(nproc) BUILD_LOG=1

tar -cJf logs.tar.xz logs
mv logs.tar.xz bin
