#/usr/bin/bash

#make stop
killall ops_server
make
make install
make run
#sudo -u postgres psql
