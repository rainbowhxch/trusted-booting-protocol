#! /bin/bash

make -C ..
make -C .. test

swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 \
                          --server type=tcp,port=2321 --flags not-need-init &
swtpm_ioctl -i --tcp :2322

../proxy-v &
../sdw-tpm &

pkill proxy-v
pkill swtpm
