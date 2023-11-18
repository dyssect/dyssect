# Dyssect: Dynamic Scaling of Stateful Network Functions

In this repository, we provide the source code, optimization models, and executation scripts for running Dyssect.

## Dependencies 

- DPDK (Data Plane Development Kit) (https://dpdk.org)
- BESS (Berkeley Extensible Software Switch) (https://github.com/NetSys/BESS)
- Gurobi Optimizer (https://gurobi.com)
  - Setting `GUROBI_HOME` environment variable
- Google's Hash Map ([libsparsehash-dev](https://packages.debian.org/sid/libsparsehash-dev) Debian package)
- Netronome nfp4build and nfp-nffw

## Installing/Compiling Dyssect
```
~$ git clone https://github.com/dyssect/dyssect
~$ cd dyssect
~$ sudo ./build.py
```

## Compiling Optimization Models
```
~$ g++ -m64 -O2 -o solver solver.cpp -I${GUROBI_HOME}/include -L${GUROBI_HOME}/lib -lgurobi_c++ -lgurobi91 -lm -Wall
```

## Running Dyssect

### FastClick

We provide source code (FastClick/*) for Dyssect in FastClick (https://github.com/tbarbette/fastclick).

### Netronome SmartNIC

We provide source code (SmartNIC/\*.p4 and SmartNIC/\*.c) for Netronome SmartNIC (Hardware, Hardware+Software, and Software).

### Model Optimizer

The controller uses Gurobi for solving the optimization models. To communicate with Gurobi, the Dyssect controller uses a named pipe for data transfer. 
[`solver.cpp`](solver.cpp) implements a daemon to receive commands from the Dyssect controller and execute the optimization models.

### BESS Configuration Script

We provide a BESS configuration script for a 2-NF Service Function Chain ([`sfc_2.bess`](bessctl/conf/sfc_2.bess)). Both NFs use the Dyssect API to manage their states.

The [first](core/modules/dynat.cc) NF is a NAT that updates the source IP address and TCP port of a packet and recomputes its IP and TCP checksums.
The [second](core/modules/dyids.cc) emulates CPU-intensive function by iterating over the packet payload. 

This script is easily customizable for your own purposes (https://github.com/NetSys/bess/wiki/Writing-a-BESS-Configuration-Script) 

### Dyssect API

The Dyssect API has the following self-explanatory functions to be used by network functions.
```
template <typename T> 

handle _init()
bool _insert<T>(handle, pkt, state)
bool _delete(handle, pkt)
T* _lookup<T>(handle, pkt)
```

We provide a [simple](core/modules/dysimple.cc) network function to exemplify the Dyssect API.

## Execution Script

To coordinate Dyssect's  execution, we provide a shell script ([`run_dyssect.sh`](run_dyssect.sh)) that can be customized with the following input parameters:
```
INCOMING_PORT=3                 # The DPDK port id for incoming packets
OUTGOING_PORT=3                 # The DPDK port id for outgoing packets
SHARDS=16                       # The number of shards
SFC_LENGTH=2                    # The length of the Service Function Chain
CORES_LIST=0,2,4,6,8,10,12,14   # The list of CPU cores to be utilized to process the packets
CONTROLLER_CORE=16              # The core to assign to Dyssect Controller
SOLVER_CORE=18                  # The core to assign to optimizer process
SCRIPT_NAME="sfc_2"             # The name of BESS configuration script (in the bessctl/conf/ directory)
PIPE_DIR="."                    # The directory for the pipe between optimizer process and Dyssect Controller
```

We can track the packet processing with the following command:
```
~$ ./bessctl/bessctl monitor pipeline
```
