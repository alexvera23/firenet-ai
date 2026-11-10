#!/usr/bin/env fish

# FireNet-AI - Automatización de Topología de Red (IPv4 e IPv6)
# Conforme a docs/ROADMAP.md (Fase 1: Día 1)
# Topología Aislada: [Client] + [Attacker] <---> [Gateway (FireNet-AI)] <---> [Target]

set NS_CLIENT client
set NS_ATTACKER attacker
set NS_GW gateway
set NS_TARGET target

# Segmento Cliente <-> Gateway (Subred 10.0.1.0/24 y fd00:1::/64)
set IP4_CLIENT 10.0.1.10/24
set IP4_GW_C 10.0.1.1/24
set IP6_CLIENT fd00:1::10/64
set IP6_GW_C fd00:1::1/64

# Segmento Attacker <-> Gateway (Subred 10.0.3.0/24 y fd00:3::/64)
set IP4_ATTACKER 10.0.3.10/24
set IP4_GW_A 10.0.3.1/24
set IP6_ATTACKER fd00:3::10/64
set IP6_GW_A fd00:3::1/64

# Segmento Gateway <-> Target (Subred 10.0.2.0/24 y fd00:2::/64)
set IP4_GW_T 10.0.2.1/24
set IP4_TARGET 10.0.2.10/24
set IP6_GW_T fd00:2::1/64
set IP6_TARGET fd00:2::10/64

function clean_netns
    echo "[*] Limpiando namespaces previos..."
    # Eliminar namespaces actuales
    sudo ip netns del $NS_CLIENT 2>/dev/null
    sudo ip netns del $NS_ATTACKER 2>/dev/null
    sudo ip netns del $NS_GW 2>/dev/null
    sudo ip netns del $NS_TARGET 2>/dev/null

    # Eliminar posibles namespaces heredados de versiones anteriores
    sudo ip netns del ns-client 2>/dev/null
    sudo ip netns del ns-gw 2>/dev/null
    sudo ip netns del ns-server 2>/dev/null
    echo "[+] Limpieza completada."
end

function setup_netns
    clean_netns

    echo "[*] 1. Creando Namespaces de red..."
    sudo ip netns add $NS_CLIENT
    sudo ip netns add $NS_ATTACKER
    sudo ip netns add $NS_GW
    sudo ip netns add $NS_TARGET

    echo "[*] 2. Creando enlaces veth bidireccionales..."
    # Enlace Client <-> Gateway
    sudo ip link add veth-c-gw type veth peer name veth-gw-c
    # Enlace Attacker <-> Gateway
    sudo ip link add veth-a-gw type veth peer name veth-gw-a
    # Enlace Gateway <-> Target
    sudo ip link add veth-gw-t type veth peer name veth-t-gw

    echo "[*] 3. Asignando interfaces a sus respectivos Namespaces..."
    sudo ip link set veth-c-gw netns $NS_CLIENT
    sudo ip link set veth-gw-c netns $NS_GW

    sudo ip link set veth-a-gw netns $NS_ATTACKER
    sudo ip link set veth-gw-a netns $NS_GW

    sudo ip link set veth-gw-t netns $NS_GW
    sudo ip link set veth-t-gw netns $NS_TARGET

    echo "[*] 4. Configurando Nodo Cliente ($NS_CLIENT)..."
    sudo ip netns exec $NS_CLIENT ip link set dev lo up
    sudo ip netns exec $NS_CLIENT ip link set dev veth-c-gw up
    sudo ip netns exec $NS_CLIENT ip addr add $IP4_CLIENT dev veth-c-gw
    sudo ip netns exec $NS_CLIENT ip -6 addr add $IP6_CLIENT dev veth-c-gw
    sudo ip netns exec $NS_CLIENT ip route add default via 10.0.1.1 dev veth-c-gw
    sudo ip netns exec $NS_CLIENT ip -6 route add default via fd00:1::1 dev veth-c-gw

    echo "[*] 5. Configurando Nodo Attacker ($NS_ATTACKER)..."
    sudo ip netns exec $NS_ATTACKER ip link set dev lo up
    sudo ip netns exec $NS_ATTACKER ip link set dev veth-a-gw up
    sudo ip netns exec $NS_ATTACKER ip addr add $IP4_ATTACKER dev veth-a-gw
    sudo ip netns exec $NS_ATTACKER ip -6 addr add $IP6_ATTACKER dev veth-a-gw
    sudo ip netns exec $NS_ATTACKER ip route add default via 10.0.3.1 dev veth-a-gw
    sudo ip netns exec $NS_ATTACKER ip -6 route add default via fd00:3::1 dev veth-a-gw

    echo "[*] 6. Configurando Nodo Target ($NS_TARGET)..."
    sudo ip netns exec $NS_TARGET ip link set dev lo up
    sudo ip netns exec $NS_TARGET ip link set dev veth-t-gw up
    sudo ip netns exec $NS_TARGET ip addr add $IP4_TARGET dev veth-t-gw
    sudo ip netns exec $NS_TARGET ip -6 addr add $IP6_TARGET dev veth-t-gw
    sudo ip netns exec $NS_TARGET ip route add default via 10.0.2.1 dev veth-t-gw
    sudo ip netns exec $NS_TARGET ip -6 route add default via fd00:2::1 dev veth-t-gw

    echo "[*] 7. Configurando Gateway FireNet-AI ($NS_GW)..."
    sudo ip netns exec $NS_GW ip link set dev lo up
    sudo ip netns exec $NS_GW ip link set dev veth-gw-c up
    sudo ip netns exec $NS_GW ip link set dev veth-gw-a up
    sudo ip netns exec $NS_GW ip link set dev veth-gw-t up

    sudo ip netns exec $NS_GW ip addr add $IP4_GW_C dev veth-gw-c
    sudo ip netns exec $NS_GW ip -6 addr add $IP6_GW_C dev veth-gw-c

    sudo ip netns exec $NS_GW ip addr add $IP4_GW_A dev veth-gw-a
    sudo ip netns exec $NS_GW ip -6 addr add $IP6_GW_A dev veth-gw-a

    sudo ip netns exec $NS_GW ip addr add $IP4_GW_T dev veth-gw-t
    sudo ip netns exec $NS_GW ip -6 addr add $IP6_GW_T dev veth-gw-t

    # Habilitar Reenvío IP (Forwarding) en el Gateway
    sudo ip netns exec $NS_GW sysctl -q -w net.ipv4.ip_forward=1
    sudo ip netns exec $NS_GW sysctl -q -w net.ipv6.conf.all.forwarding=1

    echo "[*] 8. Inicializando Firewall nftables base en Gateway..."
    set SCRIPT_DIR (dirname (status filename))
    set NFT_CONF "$SCRIPT_DIR/../firewall-baseline/nftables.conf"
    if test -f "$NFT_CONF"
        sudo ip netns exec $NS_GW nft -f "$NFT_CONF" 2>/dev/null
        if test $status -eq 0
            echo "[+] Reglas de nftables cargadas desde nftables.conf"
        else
            # Fallback en caso de incompatibilidad con rutas relativas de nft
            sudo ip netns exec $NS_GW nft add table inet firenet
            sudo ip netns exec $NS_GW nft "add chain inet firenet input { type filter hook input priority 0; policy accept; }"
            sudo ip netns exec $NS_GW nft "add chain inet firenet forward { type filter hook forward priority 0; policy accept; }"
            sudo ip netns exec $NS_GW nft "add chain inet firenet dynamic_rules { type filter hook forward priority -1; policy accept; }"
            echo "[+] Reglas base de nftables creadas inline."
        end
    end

    echo "=========================================================="
    echo "[+] Topología FireNet-AI configurada exitosamente:"
    echo "    - Client   : 10.0.1.10   | fd00:1::10"
    echo "    - Attacker : 10.0.3.10   | fd00:3::10"
    echo "    - Gateway  : 10.0.1.1 / 10.0.2.1 / 10.0.3.1"
    echo "    - Target   : 10.0.2.10   | fd00:2::10"
    echo "=========================================================="
end

function test_connectivity
    echo "[*] Probando conectividad de la topología..."
    echo -n " -> Ping Client -> Target (IPv4 10.0.2.10): "
    if sudo ip netns exec $NS_CLIENT ping -c 1 -W 1 10.0.2.10 >/dev/null 2>&1
        echo "OK"
    else
        echo "FALLO"
    end

    echo -n " -> Ping Client -> Target (IPv6 fd00:2::10): "
    if sudo ip netns exec $NS_CLIENT ping -6 -c 1 -W 1 fd00:2::10 >/dev/null 2>&1
        echo "OK"
    else
        echo "FALLO"
    end

    echo -n " -> Ping Attacker -> Target (IPv4 10.0.2.10): "
    if sudo ip netns exec $NS_ATTACKER ping -c 1 -W 1 10.0.2.10 >/dev/null 2>&1
        echo "OK"
    else
        echo "FALLO"
    end

    echo -n " -> Ping Attacker -> Target (IPv6 fd00:2::10): "
    if sudo ip netns exec $NS_ATTACKER ping -6 -c 1 -W 1 fd00:2::10 >/dev/null 2>&1
        echo "OK"
    else
        echo "FALLO"
    end
end

switch $argv[1]
    case 'clean'
        clean_netns
    case 'test' 'status'
        test_connectivity
    case 'help' '-h' '--help'
        echo "Uso: setup_netns.fish [setup|clean|test|status|help]"
        echo "  setup   : Crea la topología completa de 4 nodos y reglas nftables base (por defecto)"
        echo "  clean   : Destruye y limpia todos los namespaces y enlaces veth"
        echo "  test    : Comprueba la conectividad ICMP IPv4 e IPv6 entre los nodos"
    case '*'
        setup_netns
end
