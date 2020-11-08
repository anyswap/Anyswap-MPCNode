#!/bin/bash

set -e

BASEDIR=/bootnode
CONFDIR=$BASEDIR/conf
DATADIR=$BASEDIR/data
LOGDIR=$BASEDIR/log

mkdir -p -m 750 $CONFDIR $DATADIR $LOGDIR
chmod -R o-rwx $CONFDIR $DATADIR $LOGDIR

touch $LOGDIR/bootnode.log
chmod 640 $LOGDIR/bootnode.log

[ -e $CONFDIR/bootnode.key ] || bootnode --genkey $CONFDIR/bootnode.key
chmod 640 $CONFDIR/bootnode.key

exec bootnode --nodekey $CONFDIR/bootnode.key $@
