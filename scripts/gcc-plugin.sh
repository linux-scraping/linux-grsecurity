#!/bin/sh

echo "#include \"gcc-plugin.h\"" | $* -x c - -c -o /dev/null -I`$* -print-file-name=plugin`/include>/dev/null 2>&1 && echo "y"
