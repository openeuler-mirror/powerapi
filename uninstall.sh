#!/bin/bash

sudo systemctl stop pwrapis.service
sudo systemctl disable pwrapis.service
#sudo make uninstall
if [ -f "./build/install_manifest.txt" ];then
    cd build
    xargs rm < install_manifest.txt
    else
    rm /usr/include/pwrapic/*
    rm /usr/lib64/libpwrapi.so

    rm /usr/sbin/pwrapis
    rm /etc/sysconfig/pwrapis/pwrapis_config.ini
    rm /usr/lib/systemd/system/pwrapis.service
fi
