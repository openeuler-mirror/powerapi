#!/bin/bash

cd build
sudo make install 
sudo systemctl start pwrapis.service