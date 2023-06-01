#!/bin/bash

ip netns add demons
ip link add veth0 type veth peer name neth0
ip link set neth0 netns demons

ip netns exec demons ip link set lo up
ip netns exec demons ip link set neth0 up

ip link set veth0 up

ip addr add 172.16.0.2/24 dev veth0
ip netns exec demons ip addr add 172.16.0.3/24 dev neth0
