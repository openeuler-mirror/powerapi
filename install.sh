#!/bin/bash

cd build
sudo make install
sudo systemctl enable pwrapis.service --now