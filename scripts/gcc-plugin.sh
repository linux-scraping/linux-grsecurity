#!/bin/bash
srctree=$(dirname "$0")
gccplugins_dir=$($3 -print-file-name=plugin)
plugincc=$($1 -E - -o /dev/null -I${srctree}/../tools/gcc -I${gccplugins_dir}/include 2>&1 <<EOF
#include "gcc-common.h"
#if BUILDING_GCC_VERSION >= 4008 || defined(ENABLE_BUILD_WITH_CXX)
#warning $2 CXX
#else
#warning $1 CC
#endif
EOF
)

if [ $? -ne 0 ]
then
	exit 1
fi

if [[ "$plugincc" =~ "$1 CC" ]]
then
	echo "$1"
	exit 0
fi

if [[ "$plugincc" =~ "$2 CXX" ]]
then
plugincc=$($1 -c -x c++ -std=gnu++98 - -o /dev/null -I${srctree}/../tools/gcc -I${gccplugins_dir}/include 2>&1 <<EOF
#include "gcc-common.h"
class test {
public:
	int test;
} test = {
	.test = 1
};
EOF
)
if [ $? -eq 0 ]
then
	echo "$2"
	exit 0
fi
fi
exit 1
