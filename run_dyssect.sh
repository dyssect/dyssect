#!/bin/bash

INCOMING_PORT=3                 # The DPDK port id for incoming packets
OUTGOING_PORT=3                 # The DPDK port id for outgoing packets
SHARDS=16                       # The number of shards
SFC_LENGTH=2                    # The length of the Service Function Chain
CORES_LIST=0,2,4,6,8,10,12,14   # The list of CPU cores to be utilized to process the packets
CONTROLLER_CORE=16              # The core to assign to Dyssect Controller
SOLVER_CORE=18                  # The core to assign to optimizer process
SCRIPT_NAME="sfc_2"             # The name of BESS configuration script (in the bessctl/conf/ directory)
PIPE_DIR="."			# The directory for the pipe between optimizer process and Dyssect Controller

echo "Killing previous processes..."
pkill -9 bessd 1>/dev/null 2>/dev/null
pkill -9 solver 1>/dev/null 2>/dev/null

echo "Starting BESS daemon..."
sudo ./bessctl/bessctl daemon start

echo "Running the optimizer..."
taskset -c ${SOLVER_CORE} ./solver 1>/dev/null 2>/dev/null &

echo "Running the Dyssect..."
sudo INCOMING_PORT=${INCOMING_PORT} OUTGOING_PORT=${OUTGOING_PORT} SHARDS=${SHARDS} SFC_LENGTH=${SFC_LENGTH} CORE_LIST=${CORES_LIST} CONTROLLER_CORE=${CONTROLLER_CORE} PIPE_DIRECTORY=${PIPE_DIR} ./bessctl/bessctl run ${SCRIPT_NAME} 1>/dev/null 2>/dev/null
