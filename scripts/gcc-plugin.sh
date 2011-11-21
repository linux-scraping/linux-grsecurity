#!/bin/sh
echo -e "#include \"gcc-plugin.h\"\n#include \"tree.h\"\n#include \"tm.h\"\n#include \"rtl.h\"" | $1 -x c -shared - -o /dev/null -I`$2 -print-file-name=plugin`/include >/dev/null 2>&1 && echo "y"
