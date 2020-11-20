#!/bin/bash

set -e

BASEDIR=/mpcnode
CONFDIR=$BASEDIR/conf
DATADIR=$BASEDIR/data
LOGDIR=$BASEDIR/log

mkdir -p -m 750 $CONFDIR $DATADIR $LOGDIR
chmod -R o-rwx $CONFDIR $DATADIR $LOGDIR

touch $LOGDIR/mpcnode.log
chmod 640 $LOGDIR/mpcnode.log

exec mpcnode --nodekey $CONFDIR/node.key --datadir $DATADIR --log $LOGDIR/mpcnode.log $@
