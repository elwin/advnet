import argparse
import codecs
import itertools
import operator
import socket
import struct
import threading
import time
import typing

from p4utils.utils.helper import load_topo

from mock_socket import MockSocket

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    from mock_simple_switch import SimpleSwitchThriftAPI


class Controller(object):

    def __init__(self, base_traffic, mock: bool):
        self.mock = mock
        self.base_traffic_file = base_traffic
        self.topology = self.load_topology()
        self.controllers: typing.Dict[str, SimpleSwitchThriftAPI] = {}
        self.sockets: typing.Dict[str, socket.socket] = {}
        self.links: typing.Dict[typing.Tuple[str, str], bool] = {}
        self.last_measurements: typing.Dict[typing.Tuple, typing.List] = {}
        self.init()

    @staticmethod
    def load_topology():
        topology = load_topo('topology.json')
        for src, dst in itertools.combinations(topology.nodes, 2):
            if dst not in topology[src] or 'delay' not in topology[src][dst]:
                continue

            delay = topology[src][dst]['delay']
            if not delay.endswith('ms'):
                raise Exception('weird delay format')

            topology[src][dst]['weight'] = float(delay[:-2])

        return topology

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.connect_to_sockets()
        self.set_links()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        """Resets switches state"""
        [ctrl.reset_state() for ctrl in self.controllers.values()]

    def set_links(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            self.links[(src, dst)] = True

    def connect_to_sockets(self):
        for p4switch in self.topology.get_p4switches():
            cpu_interface = self.topology.get_cpu_port_intf(p4switch)

            if not self.mock:
                send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            else:
                send_socket = MockSocket()
            send_socket.bind((cpu_interface, 0))

            self.sockets[p4switch] = send_socket

        print(f'connected to all sockets')

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topology.get_p4switches():
            thrift_port = self.topology.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def set_table_defaults(self):
        for ctrl in self.controllers.values():
            ctrl.table_set_default("ipv4_lpm", "drop", [])
            ctrl.table_set_default("ecmp_group_to_nhop", "drop", [])

    def get_egress_port(self, src, dst):
        interface_info = self.topology.get_node_intfs(fields=['node_neigh', 'port'])
        for dst_cur, dst_port in interface_info[src].values():
            if dst == dst_cur:
                return dst_port

        raise Exception(f'no interface found between {src} and {dst}')

    def run(self):
        switches = list(self.topology.get_p4switches().keys())
        prefix = 32

        # Add table entries for directly connected hosts
        for switch in switches:
            ctrl = self.controllers[switch]

            for host in self.topology.get_hosts_connected_to(switch):
                host_ip = f'{self.topology.get_host_ip(host)}/{prefix}'
                host_mac = self.topology.get_host_mac(host)
                host_port = self.get_egress_port(switch, host)
                ctrl.table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [host_mac, str(host_port)])

        for src_switch in switches:
            for ecmp_group, dst_switch in enumerate(switches):
                if src_switch == dst_switch:
                    continue

                ctrl = self.controllers[src_switch]
                paths = self.topology.get_shortest_paths_between_nodes(src_switch, dst_switch)

                if len(paths) == 0:
                    raise Exception(f'no paths found between {src_switch} and {dst_switch}')
                elif len(paths) == 1:
                    path = paths[0]
                    for host in self.topology.get_hosts_connected_to(dst_switch):
                        host_ip = f'{self.topology.get_host_ip(host)}/{prefix}'
                        host_mac = self.topology.get_host_mac(host)
                        egress_port = self.get_egress_port(src_switch, path[1])

                        ctrl.table_add("ipv4_lpm", "set_nhop", [host_ip], [host_mac, str(egress_port)])
                else:
                    for host in self.topology.get_hosts_connected_to(dst_switch):
                        host_ip = f'{self.topology.get_host_ip(host)}/{prefix}'

                        ctrl.table_add("ipv4_lpm", "ecmp_group", [host_ip], [str(ecmp_group), str(len(paths))])

                    for i, path in enumerate(paths):
                        next_hop = path[1]
                        egress_port = self.get_egress_port(src_switch, next_hop)
                        next_hop_mac = self.topology.node_to_node_mac(src_switch, next_hop)

                        ctrl.table_add(
                            "ecmp_group_to_nhop",
                            "set_nhop",
                            [str(ecmp_group), str(i)],
                            [next_hop_mac, str(egress_port)],
                        )

    def send_heartbeat(self, src, dst):
        src_mac = self.topology.node_to_node_mac(src, dst)
        dst_mac = self.topology.node_to_node_mac(dst, src)
        egress_port = self.topology.node_to_node_port_num(src, dst)

        # ethernet
        src_bytes = b"".join([codecs.decode(x, 'hex') for x in src_mac.split(":")])
        dst_bytes = b"".join([codecs.decode(x, 'hex') for x in dst_mac.split(":")])

        # probably wrong, dst comes first, but we ignore those fields anyway (for now)
        eth = src_bytes + dst_bytes + struct.pack("!H", 0x1234)

        # heart beat
        heartbeat = egress_port << 7 | (1 << 6)  # port | cpu_bit
        heartbeat = struct.pack("!H", heartbeat)
        heartbeat = eth + heartbeat

        self.sockets[src].send(heartbeat)

        print(f'[heartbeat] sent heartbeat {src} -> {dst}')

    def switches(self):
        return list(self.topology.get_p4switches().keys())

    def monitor_rates(self):
        buffer_size = 8
        switches = list(self.topology.get_p4switches().keys())

        for src_switch, dst_switch in itertools.permutations(switches, 2):
            if self.topology.are_neighbors(src_switch, dst_switch):
                self.last_measurements[src_switch, dst_switch] = [(time.time(), 0, 0)]

        while not time.sleep(0.25):
            for src_switch, dst_switch in self.last_measurements:
                conn = src_switch, dst_switch
                ctrl = self.controllers[dst_switch]

                bytes_count, packet_count = ctrl.counter_read(
                    'port_counter',
                    # we're looking at the ingress, thus its reversed
                    self.topology.node_to_node_port_num(dst_switch, src_switch),
                )

                cur = time.time(), bytes_count, packet_count
                self.last_measurements[conn].append(cur)
                self.last_measurements[conn] = self.last_measurements[conn][-buffer_size:]
                if len(self.last_measurements[conn]) < buffer_size:
                    # only start making decisions once our buffer is filled
                    self.send_heartbeat(src_switch, dst_switch)
                    continue

                diff_lg = tuple(map(operator.sub, cur, self.last_measurements[conn][-3]))
                diff_sm = tuple(map(operator.sub, cur, self.last_measurements[conn][-2]))

                bytes_rate = diff_lg[1] / diff_lg[0] / 1000 / 1000 * 8
                packet_rate = diff_lg[2] / diff_lg[0]

                print(f'[bandwidth]: {src_switch} -> {dst_switch}: {round(bytes_rate, 2)} / {round(packet_rate, 2)}')

                if diff_sm[2] == 0:  # no change in packet in the last 0.25s
                    self.send_heartbeat(src_switch, dst_switch)

                if self.links[(src_switch, dst_switch)] and diff_lg[2] == 0:
                    print(f'[link] {src_switch} -> {dst_switch} is down')
                    self.links[(src_switch, dst_switch)] = False

                if not self.links[(src_switch, dst_switch)] and diff_sm[2] > 0:
                    print(f'[link] {src_switch} -> {dst_switch} is up')
                    self.links[(src_switch, dst_switch)] = True

    def main(self):
        """Main function"""
        self.run()

        threading.Thread(target=self.monitor_rates).start()

        time.sleep(120)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic', type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas', type=str, required=False, default='')
    parser.add_argument('--mock', action="store_true", default=False,
                        help="Enable when stuff (p4utils, sockets) should be mocked")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic, args.mock)
    controller.main()
