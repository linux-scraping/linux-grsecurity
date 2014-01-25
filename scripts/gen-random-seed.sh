#!/bin/sh

if [ ! -f 'tools/gcc/randstruct.seed' ]; then
	SEED=`od -A n -t x8 -N 32 /dev/urandom | tr -d ' \n'`
	echo "$SEED" > tools/gcc/randstruct.seed
fi

cat tools/gcc/randstruct.seed
