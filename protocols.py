import os
from collections import Counter


'''
sockets: used   Número total de sockets em uso no sistema
TCP: inuse      Sockets TCP atualmente abertos (exclui TIME_WAIT e órfãos)
TCP: orphan     Sockets TCP sem processo associado (usualmente conexões abandonadas)
TCP: tw         Conexões em estado TIME_WAIT (aguardando término completo)
TCP: alloc      Sockets TCP alocados (inuse + TIME_WAIT + outras pendentes)
TCP: mem        Memória usada por TCP em páginas (cada página normalmente = 4 KB)
UDP: inuse      Sockets UDP ativos
UDP: mem        Memória usada por UDP (em páginas)
UDPLITE: inuse  Sockets UDPLite ativos (pouco comum)
RAW: inuse      Sockets RAW (usado por ping, traceroute, etc)
'''

'''
Para obter contagem de conexões TCP por estado
'''
TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING',
}


def get_protocol_metrics():
    result = {}
    stats = {}
    with open("/proc/net/sockstat", "r") as f:
        for line in f:
            parts = line.split()
            key = parts[0].rstrip(':')
            metrics = dict(zip(parts[1::2], map(int, parts[2::2])))
            result[key] = metrics
    for k,v in result.items():
        if k == "TCP":
            stats['socket_tcp'] = v
        elif k == "UDP":
            stats['socket_udp'] = v
        elif k == "sockets":
            stats['sockets'] = v
    return stats


def get_tcp_states():
    state_counter_v4 = Counter()
    state_counter_v6 = Counter()
    with open("/proc/net/tcp", "r") as f:
        next(f)  # skip header
        for line in f:
            fields = line.strip().split()
            state_hex = fields[3]
            state = TCP_STATES.get(state_hex.upper(), 'UNKNOWN')
            state_counter_v4[state] += 1
    with open("/proc/net/tcp6", "r") as f:
        next(f)  # skip header
        for line in f:
            fields = line.strip().split()
            state_hex = fields[3]
            state = TCP_STATES.get(state_hex.upper(), 'UNKNOWN')
            state_counter_v6[state] += 1

    return {'tcp_state_v4': state_counter_v4, 'tcp_state_v6': state_counter_v6} 
