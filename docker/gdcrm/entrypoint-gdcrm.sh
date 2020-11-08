#!/bin/bash

set -e

BASEDIR=/gdcrm
CONFDIR=$BASEDIR/conf
DATADIR=$BASEDIR/data
LOGDIR=$BASEDIR/log

mkdir -p -m 750 $CONFDIR $DATADIR $LOGDIR
chmod -R o-rwx $CONFDIR $DATADIR $LOGDIR

touch $LOGDIR/gdcrm.log
chmod 640 $LOGDIR/gdcrm.log

exec gdcrm --nodekey $CONFDIR/node.key --datadir $DATADIR --log $LOGDIR/gdcrm.log $@
