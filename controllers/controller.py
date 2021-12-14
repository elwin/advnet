import argparse
import codecs
import enum
import functools
import itertools
import logging
import operator
import socket
import struct
import sys
import time
import typing

import networkx as nx
import networkx.algorithms.simple_paths
from p4utils.utils.helper import load_topo

from constraints import load_waypoints
from mock_socket import MockSocket
from smart_switch import SmartSwitch

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    from mock_simple_switch import SimpleSwitchThriftAPI

BUFFER_SIZE = 8
MAX_PATH_LENGTH = 8
PATH_VARIATION = 10
MIN_MONITOR_WAIT = 0.25
MAX_RECOMPUTATION = 4


class Classification(enum.Enum):
    TCP = 1
    UDP = 2


def pairwise(iterable):
    # pairwise('ABCDEFG') --> AB BC CD DE EF FG
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


def time_function(f: typing.Callable):
    start = time.time()
    x = f()
    duration = time.time() - start
    duration = round(duration * 1000, 2)
    logging.info(f'[timing] executed {f.__name__} in {duration}ms')
    return x


class Controller(object):

    def __init__(self, base_traffic: str, mock: bool, slas_path: str):
        self.mock = mock
        self.base_traffic_file = base_traffic
        self.topology = self.load_topology()
        self.graph = self.load_graph()
        self.controllers: typing.Dict[str, SmartSwitch] = {}
        self.sockets: typing.Dict[str, socket.socket] = {}
        self.links: typing.Dict[typing.Tuple[str, str], bool] = {}
        self.last_measurements: typing.Dict[typing.Tuple, typing.List] = {}
        self.waypoints = load_waypoints(slas_path)

    def compute_weight(self, src: str, dst: str):
        return self.topology[src][dst]['delay'] + 1
        #
        # edge = self.topology[src][dst]
        # bw_bytes, _ = self.get_bandwidth(src, dst)
        # delay = edge['delay']
        # congestion_ratio = bw_bytes / (10 * 2 ** 10)
        #
        # return delay + 20 * congestion_ratio ** 2 + 1
        # return delay  # bandwidth for now, performance becomes worse

    def recompute_weights(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            if self.graph.has_edge(src, dst):
                self.graph[src][dst]['delay'] = self.compute_weight(src, dst)
                self.graph[src][dst]['weight'] = self.graph[src][dst]['delay']
                self.graph[src][dst]['capacity'] = 10.0 * 2 ** 20 - self.get_bandwidth(src, dst)[0] * 8
                cap = self.graph[src][dst]['capacity']
                logging.info(f'[cap] {round(cap / (2 ** 20), 2)}')

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

    def load_graph(self):
        graph = nx.Graph()
        for src in self.switches():
            graph.add_node(src)

        for src, dst in itertools.combinations(self.switches(), 2):
            if self.topology.are_neighbors(src, dst):
                graph.add_edge(src, dst)

        return graph

    def reset_states(self):
        """Resets switches state"""
        [ctrl.reset_state() for ctrl in self.controllers.values()]

    def initialize_link_monitoring(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            if not self.topology.are_neighbors(src, dst):
                continue

            self.set_link_up(src, dst)
            self.last_measurements[(src, dst)] = [(time.time(), 0, 0)]

    def connect_to_sockets(self):
        for p4switch in self.topology.get_p4switches():
            cpu_interface = self.topology.get_cpu_port_intf(p4switch)

            send_socket = MockSocket() if self.mock else socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            send_socket.bind((cpu_interface, 0))

            self.sockets[p4switch] = send_socket

        logging.info(f'connected to all sockets')

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topology.get_p4switches():
            thrift_port = self.topology.get_thrift_port(p4switch)
            self.controllers[p4switch] = SmartSwitch(SimpleSwitchThriftAPI(thrift_port), p4switch)

    @functools.lru_cache(maxsize=None)
    def get_host_ip_with_subnet(self, name):
        if not self.topology.isHost(name):
            raise TypeError(f'{name} is not a host.')
        ip = self.topology.get_nodes()[name].get('ip')
        if ip is None:
            raise Exception(f'{name} has no valid IP')

        return ip

    @functools.lru_cache(maxsize=None)
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

    def recompute_paths(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            paths = self.get_paths_between_filtered(Classification.TCP, src, dst)
            self.register_paths(src, dst, paths, Classification.TCP)

            wp_constraint = next(filter(lambda c: c.src == src and c.dst == dst, self.waypoints), None)
            paths = self.get_paths_between_filtered(
                Classification.UDP, src, dst,
                via=wp_constraint.via if wp_constraint else None,
            )

            self.register_paths(src, dst, paths, Classification.UDP)

        for src in self.switches():
            self.controllers[src].apply()

    def run(self):
        self.connect_to_switches()
        self.connect_to_sockets()
        self.reset_states()
        self.initialize_link_monitoring()
        time_function(self.recompute_weights)
        time_function(self.recompute_paths)

        last_monitor = time.time()
        last_recomputation = time.time()
        while True:
            time.sleep(max(last_monitor + MIN_MONITOR_WAIT - time.time(), 0))
            last_monitor = time.time()

            should_recompute = time_function(self.monitor_rates)
            if time.time() - last_recomputation > MAX_RECOMPUTATION:
                should_recompute = True

            if should_recompute:
                time_function(self.recompute_weights)
                time_function(self.recompute_paths)
                last_recomputation = time.time()

    @functools.lru_cache(maxsize=None)
    def get_hosts_connected_to(self, dst):
        return self.topology.get_hosts_connected_to(dst)

    @functools.lru_cache(maxsize=None)
    def get_host_mac(self, host):
        return self.topology.get_host_mac(host)

    def register_paths(self, src: str, dst: str, paths: typing.List[typing.List], classification: Classification):
        # Round robin over those paths
        for path in paths:
            logging.info(f'[path] {classification.name} {src}->{dst}: {path}')

        paths = (PATH_VARIATION * paths)[:PATH_VARIATION]
        paths = sorted(paths)

        for idx, path in enumerate(paths):

            for host in self.get_hosts_connected_to(dst):
                complete_path = path + [host]
                egress_list = list(reversed(self.get_egress_list(complete_path)))
                egress_list_encoded = self.convert_to_hex(egress_list)
                egress_list_count = len(egress_list)

                host_ip = self.get_host_ip_with_subnet(host)
                host_mac = self.get_host_mac(host)

                self.controllers[src].table_add(
                    table_name='forwarding_table',
                    action_name='set_path',
                    match_keys=[host_ip, str(idx), str(classification.value)],
                    action_params=[host_mac, egress_list_encoded, str(egress_list_count)]
                )

    def get_paths_between_filtered(self, classification: Classification, src: str, dst: str,
                                   via: typing.Optional[str] = None, k: int = 4):
        paths = self.get_paths_between(classification, src, dst, via, k)
        paths = filter(lambda path: len(path) <= MAX_PATH_LENGTH, paths)
        paths = sorted(paths, key=lambda path: networkx.path_weight(self.graph, path, weight='weight'))
        paths = list(paths)

        if len(paths) == 0:
            log = f'no paths found between {src} and {dst}'
            if via is not None:
                log = f'{log} via {via}'

            raise Exception(log)

        return paths

    def get_paths_between(self, classification: Classification, src: str, dst: str, via: typing.Optional[str] = None,
                          k: int = 4):
        if via is None:
            if classification is Classification.TCP:
                return itertools.islice(nx.edge_disjoint_paths(self.graph, src, dst), k)
            elif classification is Classification.UDP:
                return itertools.islice(nx.shortest_simple_paths(self.graph, src, dst), k)
            else:
                raise Exception(f'invalid classification "{classification.name}"')

        # Must be converted to list first, otherwise the following list comprehension
        # will yield some unexpected stuff (generators and so)
        first_paths = list(self.get_paths_between(classification, src, via, k=k))
        second_paths = list(self.get_paths_between(classification, via, dst, k=k))
        paths = [
            [*first_path, *second_path[1:]]
            for first_path in first_paths
            for second_path in second_paths
        ]

        return paths

    @functools.lru_cache(maxsize=None)
    def node_to_node_port_num(self, src, dst):
        return self.topology.node_to_node_port_num(src, dst)

    @functools.lru_cache(maxsize=None)
    def node_to_node_mac(self, src, dst):
        return self.topology.node_to_node_mac(src, dst)

    def get_egress_list(self, path: typing.List[str]) -> typing.List[int]:
        egress_list = []
        for src, dst in pairwise(path):
            egress_list.append(self.node_to_node_port_num(src, dst))

        return egress_list

    @staticmethod
    def convert_to_hex(egress_path: typing.List[int]) -> str:
        out = 0
        for egress in egress_path:
            out <<= 4
            out += egress

        return hex(out)

    def send_heartbeat(self, src, dst):
        src_mac = self.node_to_node_mac(src, dst)
        dst_mac = self.node_to_node_mac(dst, src)
        egress_port = self.node_to_node_port_num(src, dst)

        # ethernet
        # noinspection PyTypeChecker
        src_bytes = b"".join([codecs.decode(x, 'hex') for x in src_mac.split(":")])
        # noinspection PyTypeChecker
        dst_bytes = b"".join([codecs.decode(x, 'hex') for x in dst_mac.split(":")])

        # probably wrong, dst comes first, but we ignore those fields anyway (for now)
        eth = src_bytes + dst_bytes + struct.pack("!H", 0x1234)

        # heart beat
        heartbeat = egress_port << 7 | (1 << 6)  # port | cpu_bit
        heartbeat = struct.pack("!H", heartbeat)
        heartbeat = eth + heartbeat

        self.sockets[src].send(heartbeat)

        logging.info(f'[heartbeat] sent heartbeat {src} -> {dst}')

    @functools.lru_cache(maxsize=None)
    def switches(self):
        return list(self.topology.get_p4switches().keys())

    def monitor_rates(self) -> bool:
        should_recompute = False

        for src, dst in self.last_measurements:
            conn = src, dst
            ctrl = self.controllers[dst]

            bytes_count, packet_count = ctrl.counter_read(
                'port_counter',
                # we're looking at the ingress, thus its reversed
                self.node_to_node_port_num(dst, src),
            )

            cur = time.time(), bytes_count, packet_count
            self.last_measurements[conn].append(cur)
            self.last_measurements[conn] = self.last_measurements[conn][-BUFFER_SIZE:]
            if len(self.last_measurements[conn]) < BUFFER_SIZE:
                # only start making decisions once our buffer is filled
                self.send_heartbeat(src, dst)
                continue

            diff_lg = tuple(map(operator.sub, cur, self.last_measurements[conn][-5]))
            diff_sm = tuple(map(operator.sub, cur, self.last_measurements[conn][-2]))

            bytes_rate = diff_lg[1] / diff_lg[0] / 1000 / 1000 * 8
            packet_rate = diff_lg[2] / diff_lg[0]

            logging.info(f'[bandwidth]: {src}->{dst}: {round(bytes_rate, 2)} / {round(packet_rate, 2)}')

            if diff_sm[2] == 0:  # no change in packet in the last measurement
                self.send_heartbeat(src, dst)

            if self.links[(src, dst)] and diff_lg[2] == 0:
                self.set_link_down(src, dst)
                should_recompute = True

            elif not self.links[(src, dst)] and diff_sm[2] > 0:
                self.set_link_up(src, dst)
                should_recompute = True

        return should_recompute

    def set_link_up(self, src, dst):
        logging.info(f'[link] {src} -> {dst} is up')
        self.links[(src, dst)] = True
        self.graph.add_edge(src, dst)

    def set_link_down(self, src, dst):
        logging.info(f'[link] {src} -> {dst} is down')
        self.links[(src, dst)] = False
        if self.graph.has_edge(src, dst):
            self.graph.remove_edge(src, dst)


if __name__ == "__main__":
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format='[%(relativeCreated)6d] %(levelname)s: %(message)s'
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic', type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas', type=str, required=False, default='')
    parser.add_argument('--mock', action="store_true", default=False,
                        help="Enable when stuff (p4utils, sockets) should be mocked")
    args = parser.parse_args()

    controller = Controller(
        base_traffic=args.base_traffic,
        mock=args.mock,
        slas_path=args.slas,
    )

    controller.run()
