import argparse
import codecs
import csv
import dataclasses
import itertools
import logging
import operator
import socket
import struct
import sys
import time
import typing

from p4utils.utils.helper import load_topo

from mock_socket import MockSocket
from smart_switch import SmartSwitch

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    from mock_simple_switch import SimpleSwitchThriftAPI

INFINITY = 8000000
BUFFER_SIZE = 8


@dataclasses.dataclass(frozen=True)
class Waypoint:
    src: str
    dst: str
    via: str


def pairwise(iterable):
    # pairwise('ABCDEFG') --> AB BC CD DE EF FG
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


class Controller(object):

    def __init__(self, base_traffic: str, mock: bool, slas_path: str):
        self.mock = mock
        self.base_traffic_file = base_traffic
        self.slas_path = slas_path
        self.topology = self.load_topology()
        self.controllers: typing.Dict[str, SmartSwitch] = {}
        self.sockets: typing.Dict[str, socket.socket] = {}
        self.links: typing.Dict[typing.Tuple[str, str], bool] = {}
        self.last_measurements: typing.Dict[typing.Tuple, typing.List] = {}
        self.old_paths = []
        self.new_paths = []
        self.waypoints: typing.List[Waypoint] = []

    def compute_weight(self, src: str, dst: str):
        if not self.links[(src, dst)]:
            return INFINITY

        edge = self.topology[src][dst]
        bw_bytes, _ = self.get_bandwidth(src, dst)
        delay = edge['delay']
        congestion_ratio = bw_bytes / (10 * 2 ** 10)

        return delay + 20 * congestion_ratio ** 2 + 1
        # return delay  # bandwidth for now, performance becomes worse

    def set_all_weights(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            if self.topology.are_neighbors(src, dst):
                self.topology[src][dst]['weight'] = self.compute_weight(src, dst)

    @staticmethod
    def load_topology():
        topology = load_topo('topology.json')
        for src, dst in itertools.combinations(topology.nodes, 2):
            if not topology.are_neighbors(src, dst) or topology.isHost(src) or topology.isHost(dst):
                continue

            delay = topology[src][dst]['delay']
            if not delay.endswith('ms'):
                raise Exception('weird delay format')
            delay = float(delay[:-2])

            topology[src][dst]['delay'] = delay

        return topology

    def load_slas(self):
        with open(self.slas_path) as csv_file:
            for row in csv.reader(csv_file):
                if not row[0].startswith('wp_'):
                    continue

                self.waypoints.append(Waypoint(
                    src=row[1][:3],
                    dst=row[2][:3],
                    via=row[7],
                ))

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        # self.load_slas()
        self.connect_to_switches()
        # self.connect_to_sockets()
        self.reset_states()
        # self.set_links()

    def reset_states(self):
        """Resets switches state"""
        [ctrl.reset_state() for ctrl in self.controllers.values()]

    def set_links(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            if not self.topology.are_neighbors(src, dst):
                continue

            self.links[(src, dst)] = True
            self.last_measurements[(src, dst)] = [(time.time(), 0, 0)]

    def install_macs(self):
        for switch, control in self.controllers.items():
            for neighbor in self.topology.get_neighbors(switch):
                mac = self.topology.node_to_node_mac(neighbor, switch)
                port = self.topology.node_to_node_port_num(switch, neighbor)
                control.table_add(
                    table_name='rewrite_mac',
                    action_name='rewriteMac',
                    match_keys=[str(port)],
                    action_params=[str(mac)],
                )

    def connect_to_sockets(self):
        for p4switch in self.topology.get_p4switches():
            cpu_interface = self.topology.get_cpu_port_intf(p4switch)

            if not self.mock:
                send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            else:
                send_socket = MockSocket()
            send_socket.bind((cpu_interface, 0))

            self.sockets[p4switch] = send_socket

        logging.info(f'connected to all sockets')

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topology.get_p4switches():
            thrift_port = self.topology.get_thrift_port(p4switch)
            self.controllers[p4switch] = SmartSwitch(SimpleSwitchThriftAPI(thrift_port), p4switch)

    def get_host_ip_with_subnet(self, name):
        if not self.topology.isHost(name):
            raise TypeError(f'{name} is not a host.')
        ip = self.topology.get_nodes()[name].get('ip')
        if ip is None:
            raise Exception(f'{name} has no valid IP')

        return ip

    def get_egress_port(self, src, dst):
        interface_info = self.topology.get_node_intfs(fields=['node_neigh', 'port'])
        for dst_cur, dst_port in interface_info[src].values():
            if dst == dst_cur:
                return dst_port

        raise Exception(f'no interface found between {src} and {dst}')

    def get_bandwidth(self, src, dst):
        link_bw = self.last_measurements[(src, dst)]

        if len(link_bw) < 2:
            logging.info(f'[bandwidth] no bandwidth for {src} -> {dst} yet')
            return 0, 0

        diff = tuple(map(operator.sub, link_bw[0], link_bw[-1]))

        bytes_rate = diff[1] / diff[0]
        packet_rate = diff[2] / diff[0]

        return bytes_rate, packet_rate

    def recompute(self):
        self.old_paths = self.new_paths
        self.new_paths = []
        logging.info('[info] recomputing weights')
        self.set_all_weights()
        logging.info('[info] recomputing and configuring paths')
        start = time.time()
        self.run()
        logging.info(f'[info] run completed in {time.time() - start}s')

        added_paths = set(map(tuple, self.new_paths)) - set(map(tuple, self.old_paths))
        deleted_paths = set(map(tuple, self.old_paths)) - set(map(tuple, self.new_paths))

        for path in sorted(list(map(list, added_paths))):
            logging.info(f'[path] added {path}')

        for path in sorted(list(map(list, deleted_paths))):
            logging.info(f'[path] removed {path}')

    def run(self):
        for src in self.switches():
            for host in self.topology.get_hosts_connected_to(src):
                host_ip = self.get_host_ip_with_subnet(host)
                host_mac = self.topology.get_host_mac(host)
                next_hop_egress = self.get_egress_port(src, host)

                self.controllers[src].table_add(
                    table_name='ipv4_lpm',
                    action_name='set_nhop',
                    match_keys=[host_ip],
                    action_params=[host_mac, str(next_hop_egress), '1', '0x0']
                )

        for src, dst in itertools.permutations(self.switches(), 2):
            paths = self.topology.get_shortest_paths_between_nodes(src, dst)
            if len(paths) == 0:
                raise Exception(f'no paths found between {src} and {dst}')

            path = paths[0]
            next_hop = path[1]
            next_hop_mac = self.topology.node_to_node_mac(src, next_hop)
            next_hop_egress = self.topology.node_to_node_port_num(src, next_hop)

            for host in self.topology.get_hosts_connected_to(dst):
                host_path = path + tuple([host])
                egress_list = list(reversed(self.get_egress_list(host_path)))
                converted = self.convert_to_hex(egress_list)

                host_ip = self.get_host_ip_with_subnet(host)
                host_mac = self.topology.get_host_mac(host)

                self.controllers[src].table_add(
                    table_name='ipv4_lpm',
                    action_name='set_nhop',
                    match_keys=[host_ip],
                    action_params=[host_mac, converted]
                )

        for switch in self.switches():
            self.controllers[switch].apply()

    def get_egress_list(self, path: typing.List[str]) -> typing.List[int]:
        egress_list = []
        for src, dst in pairwise(path):
            egress_list.append(self.topology.node_to_node_port_num(src, dst))

        return egress_list

    @staticmethod
    def convert_to_hex(egress_path: typing.List[int]) -> str:
        out = 0
        for egress in egress_path:
            out <<= 4
            out += egress

        return hex(out)

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

        logging.info(f'[heartbeat] sent heartbeat {src} -> {dst}')

    def switches(self):
        return list(self.topology.get_p4switches().keys())

    def monitor_rates(self) -> bool:
        should_recompute = False

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
            self.last_measurements[conn] = self.last_measurements[conn][-BUFFER_SIZE:]
            if len(self.last_measurements[conn]) < BUFFER_SIZE:
                # only start making decisions once our buffer is filled
                self.send_heartbeat(src_switch, dst_switch)
                continue

            diff_lg = tuple(map(operator.sub, cur, self.last_measurements[conn][-5]))
            diff_sm = tuple(map(operator.sub, cur, self.last_measurements[conn][-2]))

            bytes_rate = diff_lg[1] / diff_lg[0] / 1000 / 1000 * 8
            packet_rate = diff_lg[2] / diff_lg[0]

            logging.info(
                f'[bandwidth]: {src_switch} -> {dst_switch}: {round(bytes_rate, 2)} / {round(packet_rate, 2)}')

            if diff_sm[2] == 0:  # no change in packet in the last 0.25s
                self.send_heartbeat(src_switch, dst_switch)

            if self.links[(src_switch, dst_switch)] and diff_lg[2] == 0:
                self.set_link_down(src_switch, dst_switch)
                should_recompute = True

            elif not self.links[(src_switch, dst_switch)] and diff_sm[2] > 0:
                self.set_link_up(src_switch, dst_switch)
                should_recompute = True

        return should_recompute

    def set_link_down(self, src, dst):
        self.set_link(src, dst, up=False)
        self.set_link(dst, src, up=False)

    def set_link_up(self, src, dst):
        self.set_link(src, dst, up=True)
        self.set_link(dst, src, up=True)

    def set_link(self, src, dst, up: bool):
        if up:
            logging.info(f'[link] {src} -> {dst} is up')
            self.links[(src, dst)] = True

        else:
            logging.info(f'[link] {src} -> {dst} is down')
            self.links[(src, dst)] = False

        egress_port = self.topology.node_to_node_port_num(src, dst)
        self.controllers[src].register_write(
            register_name='linkState',
            index=egress_port,
            value=0 if up else 1,
        )

    def main(self):
        self.run()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic', type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas', type=str, required=False, default='')
    parser.add_argument('--mock', action="store_true", default=False,
                        help="Enable when stuff (p4utils, sockets) should be mocked")
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format='[%(relativeCreated)6d] %(levelname)s: %(message)s'
    )

    args = get_args()
    controller = Controller(
        base_traffic=args.base_traffic,
        mock=args.mock,
        slas_path=args.slas,
    )
    controller.init()
    controller.main()
