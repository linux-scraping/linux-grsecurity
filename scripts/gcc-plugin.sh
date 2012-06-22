#!/bin/bash
plugincc=`$1 -x c -shared - -o /dev/null -I\`$3 -print-file-name=plugin\`/include 2>&1 <<EOF
#include "gcc-plugin.h"
#include "tree.h"
#include "tm.h"
#include "rtl.h"
#ifdef ENABLE_BUILD_WITH_CXX
#warning $2
#else
#warning $1
#endif
EOF`
if [ $? -eq 0 ]
then
	[[ "$plugincc" =~ "$1" ]] && echo "$1"
	[[ "$plugincc" =~ "$2" ]] && echo "$2"
fi
