import os
import time
import re
from collections import Counter
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


gauge = Gauge('gauge_name', 'gauge description')

class FirewallCollector(object):
    def __init__(self):
        pass

    def collect(self):
        '''
        Metric Definitions

        '''

        self.physical_groups = {
           'channelStats': { 'fields': [ 'arm', 'eq_rearm', 'events', 'force_irq', 'poll' ],
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
                physicalInterfaces = GaugeMetricFamily('vf_interfaces','VF Interfaces Definitions',
                                                           labels=['interface', 'pf', 'type', 'address', 'mtu', 'speed', 'duplex'])
                physicalInterfaces.add_metric([interface, pf, type, address, mtu, speed, duplex], '1')
            else:
                if 'PF' in type:
                    physicalInterfaces = GaugeMetricFamily('pf_interfaces','PF Interfaces Definitions',
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                elif 'PCI' in type:
                    physicalInterfaces = GaugeMetricFamily('non_srvio_interfaces','non SRVIO Interfaces Definitions',
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                else:
                    physicalInterfaces = GaugeMetricFamily('virtual_interfaces','Virtual Interfaces Definitions',
                                                               labels=['interface', 'type', 'address', 'mtu', 'speed', 'duplex'])
                physicalInterfaces.add_metric([interface, type, address, mtu, speed, duplex], '1')

            yield physicalInterfaces


            if type != "Virtual - no hardware":
                stats = physicalFunction.parse_ethtool_stats(interface)
                for k,v in stats.items(): # rxqueues [ { net_load_rx
                    for elem in v: # v =  net_load_rx: [ { 'interface', 'queue', <metric> --- rxErrors
                        for elemk, elemv in elem.items(): # net_load_rx [{ 'interface', 'queue', <metric>
                            if elemk in self.physical_groups:
                                group = self.physical_groups[elemk]
                                labels = group['labels']
                                metric_value = None
                                label_list = []
                                for vdata in elemv:
                                    metric_value = None
                                    label_list = []
                                    for name,value in vdata.items():
                                        if name in labels:
                                            label_list.append(value)
                                        else:
                                            metric_name = name
                                            metric_value = value
                                    if metric_value is not None:
                                        nelemk = elemk
                                        if 'rx' in nelemk and 'rx' in metric_name:
                                            nelemk = nelemk.replace("_rx", "")
                                        elif 'tx' in nelemk and 'tx' in metric_name:
                                            nelemk = nelemk.replace("_tx", "")
                                        metr = f"{nelemk}_{metric_name}"  
                                        metr = metr.replace(" ", "_")
                                        metric = GaugeMetricFamily(metr, f"{metrics_descriptions[metric_name]['description']}", labels=labels)
                                        metric.add_metric(label_list, metric_value)
                                        yield metric
            else:
                stats = physicalFunction.parse_ethtool_virtual(interface)
                if stats:
                    for group, values in stats.items():
                        if group in self.virtual_groups:
                            gr = self.virtual_groups[group]
                            labels = gr['labels']
                            for k,v in values.items():
                                if v is not None:
                                    grupo = group
                                    if 'rx' in grupo and 'rx' in k:
                                        grupo = grupo.replace("_rx", "")
                                    elif 'tx' in grupo and 'tx' in k:
                                        grupo = grupo.replace("_tx", "")
                                    metr = f"{grupo}_{k}" # net_load_rx + bytes
                                    metr = metr.replace(" ", "_")
                                    metric = GaugeMetricFamily(metr, f"{metrics_descriptions[k]['description']}", labels=labels)
                                    label_list = [ interface ]
                                    metric.add_metric(label_list, v)
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

        pool_metrics = []
        stats = numa.get_nodes()
        for met_name, values in stats.items():
            if 'numa' in met_name:
                a_metr = met_name.split("_")
                metr = a_metr[1]
                title = met_name
            else:
                metr = met_name
                title = 'numa' + "_" + met_name
            if title not in pool_metrics:
                metric = GaugeMetricFamily(title, f"{metrics_descriptions[metr]['description']}", labels=['node'])
                pool_metrics.append(title)
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
