#!/bin/bash

BINPATH=/src/bin/cmd

echo "Generating bootnode key..."
NAME=bootnode_key_init DARGS="--rm" ./run.sh $BINPATH/bootnode --genkey bootnode.key

echo "Starting bootnode..." # CORRECT
NAME=bootnode DARGS="--rm -d" ./run.sh $BINPATH/bootnode --nodekey ./bootnode.key --addr :5550 --group 0 --nodes 3

# parse bootnode (enode) address from docker logs, store in file
docker logs bootnode | head -n 3 | tail -n 1 | awk -F, '{print $2}' | awk '{print $2}' > data/enode.txt
# format enode IP address for docker
# BOOTNODE_ADDR=$(cat data/enode.txt)
BOOTNODE_ADDR="$(sed 's/\[::\]/127.0.0.1/g' data/enode.txt)"
echo bootnode address:
echo $BOOTNODE_ADDR

echo "Generating node keys..."
NAME=dcrm_genkey1 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --genkey node1.key $1 > /dev/null
NAME=dcrm_genkey2 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --genkey node2.key $1 > /dev/null
NAME=dcrm_genkey3 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --genkey node3.key $1 > /dev/null

echo "Running (3) dcrm nodes..."

# NAME=dcrm_node1 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --rpcport 9011 --bootnodes "$BOOTNODE_ADDR" --port 12341 --nodekey "node1.key"
# NAME=dcrm_node2 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --rpcport 9012 --bootnodes "$BOOTNODE_ADDR" --port 12342 --nodekey "node2.key"
# NAME=dcrm_node3 DARGS="--rm -d" ./run.sh $BINPATH/gdcrm --rpcport 9013 --bootnodes "$BOOTNODE_ADDR" --port 12343 --nodekey "node3.key"
