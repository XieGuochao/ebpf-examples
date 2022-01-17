#!/bin/sh

# kernel-check.sh
# Author: Guochao
# Created on 17-01-2022

# This script is based on https://github.com/iovisor/bcc/blob/master/INSTALL.md

CONFIG_FILE="/boot/config-`uname -r`"
CONFIG="kernel-config"
CONFIG_NETWORKING="kernel-networking"

echo "Requried:"

check_config() {
    config=$1
    grep $config $CONFIG_FILE || (echo "\nMissing: $config" \
    && grep ${config%=*} $CONFIG_FILE && echo "") 
}

for config in `cat $CONFIG`
do
    check_config $config
done

echo ""
echo "For networking example:"

for config in `cat $CONFIG_NETWORKING`
do
    check_config $config
done
