#!/bin/bash
srctree=$(dirname "$0")
gccplugins_dir=$($3 -print-file-name=plugin)
plugincc=$($1 -E -shared - -o /dev/null -I${srctree}/../tools/gcc -I${gccplugins_dir}/include 2>&1 <<EOF
#include "gcc-common.h"
#if BUILDING_GCC_VERSION >= 4008 || defined(ENABLE_BUILD_WITH_CXX)
#warning $2
#else
#warning $1
#endif
EOF
)
if [ $? -eq 0 ]
then
	( [[ "$plugincc" =~ "$1" ]] && echo "$1" ) || ( [[ "$plugincc" =~ "$2" ]] && echo "$2" )
fi
