#!/bin/bash

ip netns add database
ip link add veth1 type veth peer name neth1
ip link set neth1 netns database

ip netns exec database ip link set lo up
ip netns exec database ip link set neth1 up

ip link set veth1 up

ip addr add 172.16.0.4/24 dev veth1
ip netns exec database ip addr add 172.16.0.5/24 dev neth1
