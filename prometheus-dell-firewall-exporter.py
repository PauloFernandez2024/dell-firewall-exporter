import os
import time
import re
from collections import Counter, defaultdict
import copy
import json
import yaml
import physicalFunction
import protocols
import numa
import procs
import moncpu
from metrics_descriptions_sorted import metrics_descriptions
from prometheus_client import start_http_server
from prometheus_client.core import Gauge, GaugeMetricFamily, CounterMetricFamily, REGISTRY

def get_configuration():
    file = "/etc/default/prometheus-dell-firewall-exporter.yaml"
    #file = "prometheus-dell-firewall-exporter.yaml"
    with open(file,"r") as file_object:
        generator_obj = yaml.load_all(file_object,Loader=yaml.SafeLoader)
        for data in generator_obj:
            config_data = data
    return config_data


def reorganize_metrics(data):
    result = {'rx_queues': {}, 'tx_queues': {}, 'channels': {} }
    for type in ['rx_queues', 'tx_queues', 'channels']:
        if type not in data:
            continue
        for grp in data[type]:
            for category, metrics in grp.items():
                if category not in result[type]:
                    result[type][category] = defaultdict(list)
                for metric in metrics:
                    interface = metric.get('interface')
                    queue = None
                    channel = None
                    if 'queue' in metric:
                        queue = metric.get('queue')
                    elif 'channel' in metric:
                        channel = metric.get('channel')
                    for key, val in metric.items():
                        if key in ('interface', 'queue', 'channel'):
                            continue
                        if queue is not None:
                            result[type][category][key].append({
                                'interface': interface,
                                'queue': queue,
                                'value': val
                            })
                        elif channel is not None:
                            result[type][category][key].append({
                                'interface': interface,
                                'channel': channel,
                                'value': val
                            })

    return result


def unify_metrics(stats_pool):
    result= defaultdict(lambda: defaultdict(list))
    for entry in stats_pool:
        for category, sub_metrics in entry.items():
            for metric_type, values in sub_metrics.items():
                result[category][metric_type].extend(values)
    return dict(result)



def merge_stats_pool(stats_pool):
    def recursive_merge(target, source):
        for key, value in source.items():
            if isinstance(value, dict):
                node = target.setdefault(key, {})
                recursive_merge(node, value)
            elif isinstance(value, list):
                target.setdefault(key, []).extend(value)
            else:
                target[key] = value

    merged = {}
    for entry in stats_pool:
        recursive_merge(merged, copy.deepcopy(entry))
    return merged


gauge = Gauge('gauge_name', 'gauge description')

class FirewallCollector(object):
    def __init__(self):
        pass

    def collect(self):
        '''
        Metric Definitions

        '''

        self.physical_groups = {
           'net_channel': { 'fields': [ 'arm', 'eq_rearm', 'events', 'force_irq', 'poll' ],
                             'labels': [ 'interface', 'channel' ]
           },

           'net_load_rx': { 'fields': [ 'LRO byte rx', 'LRO pkts rx', 'bytes', 'bcast_packets', 'bcast pkts rx', 'broadcast', 'broadcast_phy', 'gro_packets',
                                        'lro_packets', 'mcast_packets', 'mcast pkts rx', 'multicast', 'multicast_phy', 'octets', 'packets', 'ucast_packets',
                                        'ucast pkts rx' ],
                            'labels': [ 'interface', 'queue' ]
           },

           'net_fails_rx': { 'fields': [ 'align_errors', 'discards', 'discards_phy', 'drv dropped rx total', 'errors', 'errors_phy', 'fcs_errors',
                                         'frame_errors', 'frame_too_long_errors', 'no_buffer_count', 'oversize_pkts_phy', 'pkts rx OOB', 'pkts rx err',
                                         'rx buf alloc fail',  'tls_err', 'undersize_packets', 'undersize_pkts_phy', 'wqe_err', 'xdp_drop' ],
                              'labels': [ 'interface', 'queue' ]
           },

           'net_cpu_rx': { 'fields': [ 'csum_complete', 'csum_unnecessary', 'csum_none' ],
                           'labels': [ 'interface', 'queue' ]
           },

           'net_buffers_rx': { 'fields': [ 'buff_alloc_err', 'pp_alloc_fast', 'pp_alloc_slow', 'pp_recycle_cached', 'pp_recycle_ring_full',
                                           'rxbds_empty', 'xon_pause_rcvd', 'xoff_pause_rcvd' ],
                               'labels': [ 'interface', 'queue' ]
           },

           'net_security_rx': { 'fields': [ 'tls_decrypted_bytes', 'tls_err' ],
                                'labels': [ 'interface', 'queue' ]
           },

           'net_load_tx': { 'fields': [ 'TSO bytes tx', 'TSO pkts tx', 'bcast_packets', 'bcast pkts tx', 'broadcast', 'broadcast_phy', 'bytes',
                                        'drv dropped tx total', 'giant hdr', 'mcast_packets', 'mcast pkts tx', 'multicast', 'multicast_phy',
                                        'octets', 'packets', 'ring full', 'ucast_packets', 'ucast pkts tx' ],
                            'labels': [ 'interface', 'queue' ]
           },

           'net_fails_tx': { 'fields': [ 'abort_late_coll', 'cqe_err', 'discards', 'discards_phy', 'dropped', 'errors', 'errors_phy',
                                         'excessive_collisions', 'mac_errors', 'pkts tx discard', 'pkts tx err', 'stopped',
                                         'tcp_seg_failed', 'tx_timeout_count', 'xdp_err', 'xdp_full' ],
                             'labels': [ 'interface', 'queue' ]
           },

           'net_cpu_tx': { 'fields': [ 'tso_packets', 'tso_bytes', 'csum_partial', 'csum_none' ],
                           'labels': [ 'interface', 'queue' ]
           },

           'net_buffers_tx': { 'fields': [ 'xon_sent', 'xoff_sent', 'comp_queue_full' ],
                               'labels': [ 'interface', 'queue' ]
           },

           'net_security_tx': { 'fields': [ 'encrypted_packets', 'tls_drop_bypass_req', 'tls_ooo' ],
                                'labels': [ 'interface', 'queue' ]
           }
        }

        self.virtual_groups = {
            'net_load_rx': { 'fields': [ 'bytes', 'packets' ],
                             'labels': [ 'interface' ]
            },

            'net_fails_rx': { 'fields': [ 'errors' ],
                              'labels': [ 'interface' ]
            },

            'net_load_tx': { 'fields': [ 'bytes', 'packets' ],
                             'labels': [ 'interface' ]
            },

            'net_fails_tx': { 'fields': [ 'dropped' ],
                              'labels': [ 'interface' ]
            }
        }

        self.sockets = {
            'socket_tcp': [ 'alloc', 'inuse', 'mem', 'orphan', 'tw' ],
            'socket_udp': [ 'inuse', 'mem' ],
            'sockets': [ 'used' ]
        }

        self.tcp_states = {
            'tcp_state_v4': [ 'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'CLOSE',
                              'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'CLOSING', 'UNKNOWN' ],
            'tcp_state_v6': [ 'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'CLOSE',
                              'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'CLOSING', 'UNKNOWN' ]
        }

        stats_virtual_pool = []
        stats_pool = []

        for iface in physicalFunction.get_physical_interfaces():
            interface = iface['interface']
            type = iface['type']
            address = iface['address']
            mtu = iface['mtu']
            speed = iface['speed']
            duplex = iface['duplex']
            if 'VF' in type:
                pf = physicalFunction.get_vf(interface)
                if pf is None:
                    pf = "unknown"
                metric_name = 'vf_interface' + "_" + interface
                metric_name = metric_name.replace("-", "_")
                physicalInterfaces = GaugeMetricFamily(metric_name, f"{interface} VF Interfaces Definitions",
                                                       labels=['interface', 'pf', 'type', 'address', 'mtu', 'speed', 'duplex'])
                physicalInterfaces.add_metric([interface, pf, type, address, mtu, speed, duplex], '1')
            else:
                if 'PF' in type:
                    metric_name = 'pf_interface' + "_" + interface
                    metric_name = metric_name.replace("-", "_")
                    physicalInterfaces = GaugeMetricFamily(metric_name, f"{interface} PF Interfaces Definitions",
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                elif 'PCI' in type:
                    metric_name = 'non_srvio_interface' + "_" + interface
                    metric_name = metric_name.replace("-", "_")
                    physicalInterfaces = GaugeMetricFamily(metric_name,f"{interface} non SRVIO Interfaces Definitions",
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                else:
                    metric_name = 'virtual_interface' + "_" + interface
                    metric_name = metric_name.replace("-", "_")
                    physicalInterfaces = GaugeMetricFamily(metric_name, f"{interface} Virtual Interfaces Definitions",
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                physicalInterfaces.add_metric([interface, type, address, mtu, speed, duplex], '1')

            yield physicalInterfaces


            if type != "Virtual - no hardware":
                stats = physicalFunction.parse_ethtool_stats(interface)
                new_stats = reorganize_metrics(stats)
                stats_pool.append(new_stats)
            else:
                stats = physicalFunction.parse_ethtool_virtual(interface)
                stats_virtual_pool.append(stats)

        if stats_pool:
           new_stats = merge_stats_pool(stats_pool)
           if new_stats:
               for type in new_stats:
                    queues = new_stats[type]
                    for rxcategory in queues:
                        group = self.physical_groups[rxcategory]
                        labels = group['labels']
                        for metric_name in queues[rxcategory]:
                            categ = rxcategory
                            if 'rx' in metric_name:
                                categ = categ.replace("_rx", "")
                            elif 'tx' in metric_name:
                                categ = categ.replace("_tx", "")
                            metr = f"{categ}_{metric_name}".replace(" ", "_")
                            metric = GaugeMetricFamily(metr, f"{metrics_descriptions[metric_name]['description']}", labels=labels)
                            for values in queues[rxcategory][metric_name]:
                                result = None
                                label_list = []
                                for k,v in values.items():
                                    if k != "value":
                                        label_list.append(v)
                                    else:
                                        result = v
                                if result is not None:
                                    metric.add_metric(label_list, result)
                            yield metric

        if stats_virtual_pool:
            new_stats = unify_metrics(stats_virtual_pool)
            if new_stats:
                for rxcategory in new_stats:
                    group = self.physical_groups[rxcategory]
                    labels = group['labels']
                    for metric_name in new_stats[rxcategory]:
                        categ = rxcategory
                        if 'rx' in metric_name:
                           categ = categ.replace("_rx", "")
                        elif 'tx' in metric_name:
                            categ = categ.replace("_tx", "")
                        metr = f"{categ}_{metric_name}".replace(" ", "_")
                        metric = GaugeMetricFamily(metr, f"{metrics_descriptions[metric_name]['description']}", labels=labels)
                        for values in new_stats[rxcategory][metric_name]:
                            result = None
                            label_list = []
                            for k,v in values.items():
                                if k != "value":
                                    label_list.append(v)
                                else:
                                    result = v
                            if result:
                                metric.add_metric(label_list, result)
                        yield metric


        stats = protocols.get_protocol_metrics()
        for group, values in self.sockets.items():
            for value in values:
                metr = group + "_" + value
                metric_value = stats[group].get(value)
                if metric_value is not None:
                    metric = GaugeMetricFamily(metr, f"{metrics_descriptions[value]['description']}", labels=[])
                    metric.add_metric([], metric_value)
                    yield metric

        stats = protocols.get_tcp_states()
        for group, values in self.tcp_states.items():
            for value in values:
                metric_value = stats[group].get(value)
                if metric_value is not None:
                    metric = GaugeMetricFamily(group, f"{metrics_descriptions[value]['description']}", labels=['state'])
                    metric.add_metric([value], metric_value)
                    yield metric

        stats = numa.get_nodes()
        for met_name, values in stats.items():
            metric = GaugeMetricFamily(met_name, f"{metrics_descriptions[met_name]['description']}", labels=['node'])
            for node, node_value in values.items():
                metric.add_metric([node], node_value)
            yield metric


        metric = GaugeMetricFamily("processes_openfiles", "Open Files", labels=['command', 'pid'])
        stats = procs.get_openfiles()
        for proc in stats['processes']:
            command = proc['command']
            open_fds = proc['open_fds']
            pid = proc['pid']
            metric.add_metric([command, pid], open_fds)
        yield metric


        cpu_data = moncpu.get_cpu_scaling_info()
        if cpu_data:
            metric = GaugeMetricFamily("cpu_freq_khz", "CPU Frequencies", labels=['index', 'current', 'governor'])
            for core, info in cpu_data.items():
                current = info['cur_freq_khz']
                governor = info['governor']
                core = str(core)
                metric.add_metric([core, current, governor], '1')
            yield metric


        stats = moncpu.get_rapl_power()
        if stats is not None:
            metric = GaugeMetricFamily("cpu_power_watts", "CPU Power", labels=['metric'])
            for metr, metr_value in stats.items():
                metric.add_metric([metr], metr_value)
            yield metric


        metric = GaugeMetricFamily("ipmi", "IpmiTool", labels=['metric'])
        stats = moncpu.get_ipmi()
        if stats:
            for metr, metr_value in stats.items():
                metric = GaugeMetricFamily(metr, " metr IpmiTool", labels=[])
                metric.add_metric([], metr_value)
            yield metric


if __name__ == "__main__":
    config = get_configuration()
    exporter = config['exporter']
    port = exporter['port']
    timeout = exporter['timeout']
    REGISTRY.register(FirewallCollector())
    start_http_server(port)
    while True:
        time.sleep(timeout)
