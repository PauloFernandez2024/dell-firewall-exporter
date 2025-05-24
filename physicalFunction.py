import os
import subprocess
import re
import json

statistic_groups = [ { 'net_load_rx': [ 'ucast pkts rx', 'mcast pkts rx', 'bcast pkts rx', 'LRO pkts rx', 'LRO byte rx' ],
                       'net_fails_rx': [ 'pkts rx OOB', 'pkts rx err', 'drv dropped rx total', 'rx buf alloc fail' ],
                       'net_load_tx': [ 'TSO pkts tx', 'TSO bytes tx', 'ucast pkts tx', 'mcast pkts tx', 'bcast pkts tx' ],
                       'net_fails_tx': [ 'pkts tx err', 'pkts tx discard', 'drv dropped tx total', 'ring full', 'giant hdr' ] },

                     { 'net_load_rx' : [ 'octets', 'ucast_packets', 'mcast_packets', 'bcast_packets' ],
                       'net_fails_rx' : [ 'fcs_errors', 'discards', 'errors', 'frame_too_long_errors', 'undersize_packets'  ],
                       'net_buffers_rx' : [ 'xon_pause_rcvd', 'xoff_pause_rcvd', 'rxbds_empty' ],
                       'net_load_tx' : [ 'octets', 'ucast_packets', 'mcast_packets', 'bcast_packets' ],
                       'net_fails_tx' : [ 'mac_errors', 'discards', 'mac_errors', 'excessive_collisions' ],
                       'net_buffers_tx' : [ 'xon_sent', 'xoff_sent', 'comp_queue_full' ] },

                     { 'net_channel': [ 'arm', 'eq_rearm', 'events', 'force_irq', 'poll' ],
                       'net_load_rx': [ 'gro_packets', 'lro_packets', 'packets', 'bytes', 'broadcast_phy', 'multicast_phy' ],
                       'net_fails_rx': [ 'wqe_err', 'xdp_drop', 'tls_err', 'discards_phy', 'errors_phy', 'oversize_pkts_phy', 'undersize_pkts_phy' ],
                       'net_cpu_rx': [ 'csum_complete', 'csum_unnecessary', 'csum_none' ],
                       'net_buffers_rx': [ 'pp_alloc_fast', 'buff_alloc_err', 'pp_alloc_slow', 'pp_recycle_cached', 'pp_recycle_ring_full' ],
                       'net_security_rx': [ 'tls_decrypted_bytes', 'tls_err' ],
                       'net_load_tx': [ 'packets', 'bytes', 'broadcast_phy', 'multicast_phy' ],
                       'net_fails_tx': [ 'stopped', 'cqe_err', 'xdp_err', 'xdp_full', 'discards_phy', 'errors_phy' ],
                       'net_cpu_tx': [ 'tso_packets', 'tso_bytes', 'csum_partial', 'csum_none' ],
                       'net_security_tx': [ 'encrypted_packets', 'tls_drop_bypass_req', 'tls_ooo' ] },

                     { 'net_load_rx': [ 'bytes', 'broadcast', 'multicast', 'packets' ],
                       'net_fails_rx': [ 'align_errors', 'errors', 'frame_errors', 'no_buffer_count' ],
                       'net_load_tx': [ 'bytes', 'broadcast', 'multicast', 'packets' ],
                       'net_fails_tx': [ 'abort_late_coll', 'dropped', 'errors', 'tcp_seg_failed', 'tx_timeout_count' ] }
]

search_model = [ "TSO pkts tx", "ring_status_update", "ch_poll", "tx_timeout_count" ]


def get_physical_interfaces():
    base_path = "/sys/class/net"
    interfaces = []

    iface_names = os.listdir("/sys/class/net")
    for iface in iface_names:
        path = f"/sys/class/net/{iface}"
        device_path = os.path.join(path, "device")
        sriov_path = os.path.join(device_path, "sriov_totalvfs")
        physfn_path = os.path.join(device_path, "physfn")
        if not os.path.exists(device_path):
            type = "Virtual - no hardware"
        elif os.path.exists(sriov_path):
            type = "PF - Physical Function with SR-IOV"
        elif os.path.exists(physfn_path):
            type = "VF - Virtual Function"
        else:
            type = "General - PCI, no SR-IOV"
        mtu = get_metric(iface, 'mtu')
        address = get_metric(iface, 'address')
        speed = get_metric(iface, 'speed')
        duplex = get_metric(iface, 'duplex')
        interfaces.append({'interface': iface, 'type': type, 'mtu': mtu, 'address': address, 'speed': speed, 'duplex': duplex})
    return interfaces


def get_vf(iface):
    pf_iface = None
    physfn_path = f"/sys/class/net/{iface}/device/physfn"
    if os.path.islink(physfn_path):
        pf_pci = os.path.basename(os.readlink(physfn_path))
        net_dir = f"/sys/bus/pci/devices/{pf_pci}/net/"
        try:
            pf_iface = os.listdir(net_dir)[0]  # Assume apenas 1 interface ligada
        except IndexError:
            return None
    return pf_iface


def get_metric(interface, metric):
    try:
        with open(f"/sys/class/net/{interface}/{metric}", "r") as fd:
            val = fd.read().strip()
        fd.close()
    except OSError as e:
        val = "unknown"
    return val


def parse_ethtool_stats(interface):
    stats = {'rx_queues': [], 'tx_queues': [], 'channels': []}
    values = {}
    queue = None
    try:
        output = subprocess.check_output(["ethtool", "-S", interface], text=True)
    except subprocess.CalledProcessError:
        return stats
    for line in output.splitlines():
        if ':' in line and 'statistic' not in line:
            key, value = line.strip().split(':', 1)
            if 'Rx Queue' in key:
                if values:  # Salva valores anteriores, se existirem
                    if queue is not None:  # Verifica se queue foi definido
                        queue.append(values)
                values = {}
                queue = stats['rx_queues']  # Define queue para rx_queues
                values['queue'] = value.strip()
                values['interface'] = interface
            elif 'Tx Queue' in key:
                if values:  # Salva valores anteriores, se existirem
                    if queue is not None:  # Verifica se queue foi definido
                        queue.append(values)
                values = {}
                queue = stats['tx_queues']  # Define queue para tx_queues
                values['queue'] = value.strip()
                values['interface'] = interface
            else:
                k =  key.strip()
                values[k] = value.strip()

    group = statistic_groups[0]
    if values and queue is not None:
        queue.append(values) # take the last value
        new_stats = {'rx_queues': [], 'tx_queues': [], 'channels': []}
        rxLoad = []
        rxErrors = []
        txLoad = []
        txErrors = []
        for x in stats['rx_queues']:
            interface = x['interface']
            q = x['queue']
            for k,v in x.items():
                if k != 'interface' and k != 'queue':
                    if k in group['net_load_rx']:
                        rxLoad.append({'interface': interface, 'queue': q, k: v})
                    elif k in group['net_fails_rx']:
                        rxErrors.append({'interface': interface, 'queue': q, k: v})
        new_stats['rx_queues'].append({'net_load_rx': rxLoad, 'net_fails_rx': rxErrors})

        for x in stats['tx_queues']:
            interface = x['interface']
            q = x['queue']
            for k,v in x.items():
                if k != 'interface' and k != 'queue':
                    if k in group['net_load_tx']:
                        txLoad.append({'interface': interface, 'queue': q, k: v})
                    elif k in group['net_fails_tx']:
                        txErrors.append({'interface': interface, 'queue': q, k: v})
        new_stats['tx_queues'].append({'net_load_tx': txLoad, 'net_fails_tx': txErrors})
        stats = new_stats

    elif values:
        for i in range(1, len(statistic_groups)):
            if search_model[i] in values:
                group = statistic_groups[i]
                stats = check_values(values, interface, group)
                break
    return stats


def check_values(values, interface, grp):
    stats = {'rx_queues': [], 'tx_queues': [], 'channels': []}
    for key,val in grp.items(): # exemplo net_load_rx, [ 'ucast pkts rx', 'mcast pkts rx', 'bcast pkts rx', 'LRO pkts rx', 'LRO byte rx' ]
        new_dict = {}
        if 'rx' in key:
            prefix = 'rx'
        elif 'tx' in key:
            prefix = 'tx'
        elif 'channel' in key:
            prefix = 'ch'
        for metric in val:
            sufix = f'_{metric}'
            for k, v in values.items():
                if k.startswith(prefix) and k.endswith(sufix):
                    pattern = fr'^{re.escape(prefix)}(\d*)_{re.escape(metric)}$'
                    match = re.match(pattern, k)
                    if match:
                        if prefix == 'ch':
                            channel = match.group(1) if match.group(1) else "all"
                            if channel not in new_dict:
                                new_dict[channel] = {"interface": interface, "channel": channel}
                            new_dict[channel][metric] = v
                        else:
                            queue = match.group(1) if match.group(1) else "all"
                            if queue not in new_dict:
                                new_dict[queue] = {"interface": interface, "queue": queue}
                            new_dict[queue][metric] = v
        if prefix == 'ch':
            stats['channels'].append({key: list(new_dict.values()) })
        elif prefix == 'rx':
            stats['rx_queues'].append({key: list(new_dict.values()) })
        elif prefix == 'tx':
            stats['tx_queues'].append({key: list(new_dict.values()) })
    return stats


def parse_ethtool_virtual(iface):
    stats = {}
    stat_dir = os.path.join("/sys/class/net", iface, "statistics")
    if os.path.exists(stat_dir):
        try:
            rx_bytes = open(os.path.join(stat_dir, "rx_bytes")).read().strip()
            tx_bytes = open(os.path.join(stat_dir, "tx_bytes")).read().strip()
            rx_packets = open(os.path.join(stat_dir, "rx_packets")).read().strip()
            tx_packets = open(os.path.join(stat_dir, "tx_packets")).read().strip()
            rx_err = open(os.path.join(stat_dir, "rx_errors")).read().strip()
            tx_drop = open(os.path.join(stat_dir, "tx_dropped")).read().strip()
            stats = { "net_load_rx": {"bytes": [{"interface": iface, "value": rx_bytes}], "packets": [{"interface": iface, "value": rx_packets}]},
                      "net_fails_rx": {"errors": [{"interface": iface, "value": rx_err}]},
                      "net_load_tx": {"bytes": [{"interface": iface, "value": tx_bytes}], "packets": [{"interface": iface, "value": tx_packets}]},
                      "net_fails_tx": {"dropped": [{"interface": iface, "value": tx_drop}]}
            }
        except Exception as err:
            return None
    return stats

