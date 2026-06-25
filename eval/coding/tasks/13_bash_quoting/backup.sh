#!/usr/bin/env bash
# Tar up a directory and write the archive somewhere.
#
# Usage: ./backup.sh SRC_DIR DEST_ARCHIVE
#
# BUG: the variables are unquoted, so any file or directory with a space
# in its name breaks the command — tar reads the parts as separate args.

SRC=$1
DEST=$2

if [ -z $SRC ] || [ -z $DEST ]; then
    echo "Usage: backup.sh SRC_DIR DEST_ARCHIVE"
    exit 1
fi

# BUG: unquoted $SRC — directory like "my files" → tar sees "my", "files".
tar -czf $DEST $SRC
