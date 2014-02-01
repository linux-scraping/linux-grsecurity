#!/bin/sh

if [ ! -f 'tools/gcc/randstruct.seed' ]; then
	SEED=`od -A n -t x8 -N 32 /dev/urandom | tr -d ' \n'`
	echo "$SEED" > tools/gcc/randstruct.seed
	cat tools/gcc/randstruct.seed | sha256sum | cut -d" " -f1 | tr -d "\n" > tools/gcc/randstruct.hashed_seed
fi
cat tools/gcc/randstruct.seed
