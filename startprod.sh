#!/bin/sh
# Modify the details below to suit your environment.
cd /home/ras3005/boost/ingester
source /home/ras3005/boost/ingester/venv/bin/activate && python /home/ras3005/boost/ingester/main.py >> out.log 2>&1 &

