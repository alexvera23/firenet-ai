#!/usr/bin/env fish

# FireNet-AI - Automatización de Topología de Red (IPv4 e IPv6)

set NS_CLIENT ns-client
set NS_GW ns-gateway
set NS_SERVER ns-server

set IP4_CLIENT 192.168.10.2/24
set IP4_GW_IN 192.168.10.1/24
set IP4_GW_OUT 192.168.20.1/24
set IP4_SERVER 192.168.20.2/24

set IP6_CLIENT fd00:10::2/64
set IP6_GW_IN fd00:10::1/64
set IP6_GW_OUT fd00:20::1/64
set IP6_SERVER fd00:20::2/64

function clean_netns
    echo "[*] Limpiando namespaces previos..."
    sudo ip netns del $NS_CLIENT 2>/dev/null
    sudo ip netns del $NS_GW 2>/dev/null
    sudo ip netns del $NS_SERVER 2>/dev/null
end

function setup_netns
    clean_netns

    echo "[*] Creando Namespaces..."
    sudo ip netns add $NS_CLIENT
    sudo ip netns add $NS_GW
    sudo ip netns add $NS_SERVER

    echo "[*] Creando enlaces veth..."
    sudo ip link add veth-cl type veth peer name veth-gw1
    sudo ip link add veth-gw2 type veth peer name veth-srv

    echo "[*] Asignando interfaces a Namespaces..."
    sudo ip link set veth-cl netns $NS_CLIENT
    sudo ip link set veth-gw1 netns $NS_GW
    sudo ip link set veth-gw2 netns $NS_GW
    sudo ip link set veth-srv netns $NS_SERVER

    echo "[*] Configurando Nodo Cliente ($NS_CLIENT)..."
    sudo ip netns exec $NS_CLIENT ip link set dev lo up
    sudo ip netns exec $NS_CLIENT ip link set dev veth-cl up
    sudo ip netns exec $NS_CLIENT ip addr add $IP4_CLIENT dev veth-cl
    sudo ip netns exec $NS_CLIENT ip addr add $IP6_CLIENT dev veth-cl
    sudo ip netns exec $NS_CLIENT ip route add default via 192.168.10.1 dev veth-cl
    sudo ip netns exec $NS_CLIENT ip -6 route add default via fd00:10::1 dev veth-cl

    echo "[*] Configurando Gateway FireNet-AI ($NS_GW)..."
    sudo ip netns exec $NS_GW ip link set dev lo up
    sudo ip netns exec $NS_GW ip link set dev veth-gw1 up
    sudo ip netns exec $NS_GW ip link set dev veth-gw2 up
    sudo ip netns exec $NS_GW ip addr add $IP4_GW_IN dev veth-gw1
    sudo ip netns exec $NS_GW ip addr add $IP6_GW_IN dev veth-gw1
    sudo ip netns exec $NS_GW ip addr add $IP4_GW_OUT dev veth-gw2
    sudo ip netns exec $NS_GW ip addr add $IP6_GW_OUT dev veth-gw2
    sudo ip netns exec $NS_GW sysctl -q -w net.ipv4.ip_forward=1
    sudo ip netns exec $NS_GW sysctl -q -w net.ipv6.conf.all.forwarding=1

    echo "[*] Configurando Nodo Servidor ($NS_SERVER)..."
    sudo ip netns exec $NS_SERVER ip link set dev lo up
    sudo ip netns exec $NS_SERVER ip link set dev veth-srv up
    sudo ip netns exec $NS_SERVER ip addr add $IP4_SERVER dev veth-srv
    sudo ip netns exec $NS_SERVER ip addr add $IP6_SERVER dev veth-srv
    sudo ip netns exec $NS_SERVER ip route add default via 192.168.20.1 dev veth-srv
    sudo ip netns exec $NS_SERVER ip -6 route add default via fd00:20::1 dev veth-srv

    echo "[+] Topología creada exitosamente."
end

switch $argv[1]
    case 'clean'
        clean_netns
    case '*'
        setup_netns
end