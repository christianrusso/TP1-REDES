#!/bin/bash

SOURCE=$1
NAME=$2

grep -v -E 'label="1?[0-9]"' $SOURCE > "$NAME.dot"
dot "$NAME.dot" -o "no_label_$NAME.png" -Tpng -Grankdir=LR
