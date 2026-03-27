#!/bin/bash

make
if [ $? -ne 0 ]; then
    echo "Build failed — exiting"
    exit 1
fi

echo "Starting services..."

./port_manager &
PORT_MGR_PID=$!

./conn_manager &
CONN_MGR_PID=$!

./traffic_manager &
TRAFFIC_PID=$!

./protection_manager &
PROTECTION_PID=$!

echo ""
echo "All services running. Press Ctrl+C to stop."
echo "Logs: tail -f wsmini.log"

# Wait for Ctrl+C then kill all services cleanly
trap "echo 'Stopping...'; kill $PORT_MGR_PID $CONN_MGR_PID $TRAFFIC_PID $PROTECTION_PID; exit 0" SIGINT

wait