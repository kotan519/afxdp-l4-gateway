# afxdp-l4-gateway

User-space L4 gateway built on AF_XDP.
Designed to forward traffic between a physical NIC and an OVS bridge.

## Architecture

eth0 (XDP redirect)
    ↓
AF_XDP userspace
    ↓
veth-gate
    ↓
OVS br0
    ↓
VM

## Setup

sudo ip link set dev enp4s0f1 xdp off
sudo ip link set enp4s0f1 up
