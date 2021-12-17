import argparse
import codecs
import dataclasses
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
from p4utils.utils.helper import load_topo

from constraints import load_waypoints
from mock_socket import MockSocket
from smart_switch import SmartSwitch
from utils import pairwise, time_function

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    from mock_simple_switch import SimpleSwitchThriftAPI

BUFFER_SIZE = 8
MAX_PATH_LENGTH = 8
PATH_VARIATION = 10
MIN_MONITOR_WAIT = 0.05
MAX_RECOMPUTATION = 2
DELAY_MULTIPLIER_THRESHOLD = 1.5
INFINITY = 100000000
BURST_SIZE = 700000
COMMITTED_RATIO = 2
BANDWIDTH_PER_FLOW_UDP = 1.75


class Classification(enum.Enum):
    TCP = 1
    UDP = 2


@dataclasses.dataclass
class Selection:
    path: typing.List[str]
    multiplier: int

    def __lt__(self, other):
        return self.multiplier < other.multiplier

    def __str__(self):
        return f'{self.multiplier}x: {self.path}'


def get_meter_rates_from_bw(bw):
    """Returns the CIR and PIR rates and bursts to configure
      meters at bw.

    Args:
        bw (float): desired bandwdith in mbps

    Returns:
        list: [(rate1, burst1), (rate2, burst2)]
    """

    rates = []
    burst_size = BURST_SIZE
    rates.append((0.125 * (bw / COMMITTED_RATIO), burst_size))
    rates.append((0.125 * bw, burst_size))
    return rates


class Controller(object):
    def __init__(self, base_traffic_path: str, mock: bool, slas_path: str):
        self.mock = mock
        self.topology = self.load_topology('topology.json')
        self.graph = self.load_graph()
        self.waypoints = load_waypoints(slas_path)
        self.controllers: typing.Dict[str, SmartSwitch] = {}
        self.sockets: typing.Dict[str, socket.socket] = {}
        self.links: typing.Dict[typing.Tuple[str, str], bool] = {}
        self.last_measurements: typing.Dict[typing.Tuple, typing.List] = {}
        self.waypoints = load_waypoints(slas_path)

    ####################
    # Helper functions #
    ####################

    @functools.lru_cache(maxsize=None)
    def get_host_ip_with_subnet(self, name):
        """Return the host IP including subnet of a host."""
        if not self.topology.isHost(name):
            raise TypeError(f'{name} is not a host.')
        ip = self.topology.get_nodes()[name].get('ip')
        if ip is None:
            raise Exception(f'{name} has no valid IP')

        return ip

    @functools.lru_cache(maxsize=None)
    def get_hosts_connected_to(self, dst):
        return self.topology.get_hosts_connected_to(dst)

    @functools.lru_cache(maxsize=None)
    def get_host_mac(self, host):
        return self.topology.get_host_mac(host)

    def path_weight(self, path, weight='weight'):
        return nx.path_weight(self.graph, path, weight=weight)

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

    @functools.lru_cache(maxsize=None)
    def switches(self):
        return list(self.topology.get_p4switches().keys())

    def get_encoded_egress(self, path, host) -> typing.Tuple[str, int]:
        complete_path = path + [host]
        egress_list = list(reversed(self.get_egress_list(complete_path)))
        return self.convert_to_hex(egress_list), len(egress_list)

    ##############################
    # Functions called only once #
    ##############################

    def install_macs(self):
        """Install mapping from egress to MAC."""
        for src in self.switches():
            for neighbor in self.topology.get_neighbors(src):
                mac = self.node_to_node_mac(neighbor, src)
                port = self.node_to_node_port_num(src, neighbor)
                self.controllers[src].api.table_add(
                    table_name='egress_to_mac',
                    action_name='rewrite_mac',
                    match_keys=[str(port)],
                    action_params=[str(mac)],
                )

    @staticmethod
    def load_topology(topology_path: str):
        """Load topology from the topology.json file and store in self.topology."""
        topology = load_topo(topology_path)
        for src, dst in itertools.combinations(topology.nodes, 2):
            if not topology.are_neighbors(src, dst) or topology.isHost(src) or topology.isHost(dst):
                continue

            delay = topology[src][dst]['delay']
            if not delay.endswith('ms'):
                raise Exception('weird delay format')

            topology[src][dst]['delay'] = float(delay[:-2])

        return topology

    def load_graph(self):
        """Create a new nx.Graph in self.graph, used for all path computations."""
        graph = nx.Graph()
        for src in self.switches():
            graph.add_node(src)

        for src, dst in itertools.combinations(self.switches(), 2):
            if self.topology.are_neighbors(src, dst):
                graph.add_edge(src, dst)

        return graph

    def reset_states(self):
        """Reset switches state."""
        [ctrl.api.reset_state() for ctrl in self.controllers.values()]

    def initialize_link_monitoring(self):
        """Initialize all links to up and prefill bandwidth measurement."""
        for src, dst in itertools.permutations(self.switches(), 2):
            if not self.topology.are_neighbors(src, dst):
                continue

            self.set_link_up(src, dst)
            self.last_measurements[(src, dst)] = [(time.time(), 0, 0)]

    def connect_to_sockets(self):
        """Connect to sockets used to send packets from controller."""
        for p4switch in self.topology.get_p4switches():
            cpu_interface = self.topology.get_cpu_port_intf(p4switch)

            send_socket = MockSocket() if self.mock else socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            send_socket.bind((cpu_interface, 0))

            self.sockets[p4switch] = send_socket

        logging.info(f'connected to all sockets')

    def connect_to_switches(self):
        """Connect to switches."""
        for p4switch in self.topology.get_p4switches():
            thrift_port = self.topology.get_thrift_port(p4switch)
            self.controllers[p4switch] = SmartSwitch(SimpleSwitchThriftAPI(thrift_port), p4switch)

    def initialize_meters(self):
        """Initialize all meters with UDP rate limiting."""
        for src in self.switches():
            for i in range(5):
                entry_handle = self.controllers[src].api.table_add(
                    table_name='rate_limiting',
                    action_name='limit_rate',
                    match_keys=str(i),
                    action_params=[],
                )

                rates = get_meter_rates_from_bw(BANDWIDTH_PER_FLOW_UDP)
                self.controllers[src].api.meter_set_rates(meter_name='our_meter', index=entry_handle, rates=rates)

    def initialize_registers(self):
        """Initialize all register to 0."""
        for src in self.switches():
            for register_name in ['hops_reg', 'hop_count_reg', 'flowlet_time_stamp_reg']:
                self.controllers[src].api.register_write(
                    register_name=register_name,
                    index=[0, 1023],
                    value=0,
                )

    def compute_alternative_paths(self):
        """Compute alternative paths for each (src, dst, neighbour(src)) pair, considering neighbour(src) is down."""
        for src, dst in itertools.permutations(self.switches(), 2):

            for neighbor in self.topology.get_neighbors(src):
                if not self.topology.isSwitch(neighbor):
                    continue

                edge = self.graph[src][neighbor]
                self.graph.remove_edge(src, neighbor)
                failure_egress = self.node_to_node_port_num(src, neighbor)
                try:
                    path = self.get_paths_between(Classification.UDP, src, dst, k=1)[0]

                    for host in self.topology.get_hosts_connected_to(dst):
                        host_ip = self.get_host_ip_with_subnet(host)
                        egress_list_encoded, egress_list_count = self.get_encoded_egress(path.path, host)

                        self.controllers[src].api.table_add(
                            table_name='alt_forwarding_table',
                            action_name='set_path',
                            match_keys=[str(failure_egress), str(host_ip)],
                            action_params=[egress_list_encoded, str(egress_list_count)],
                        )
                except nx.NetworkXNoPath:
                    pass
                finally:
                    self.graph.add_edge(src, neighbor, **edge)

    ###################
    # Link monitoring #
    ###################

    def get_bandwidth(self, src: str, dst: str):
        """
        Get bandwidth computed on the entire buffer.
        :param src: source switch
        :param dst: destination switch
        :return: (bytes_rate, packet_rate)
        """
        link_bw = self.last_measurements[(src, dst)]

        if len(link_bw) < 2:
            logging.warning(f'[bandwidth] no bandwidth for {src}->{dst} yet')
            return 0, 0

        diff = tuple(map(operator.sub, link_bw[0], link_bw[-1]))

        bytes_rate = diff[1] / diff[0]
        packet_rate = diff[2] / diff[0]

        return bytes_rate, packet_rate

    def send_heartbeat(self, src: str, dst: str):
        """
        Send heartbeat from src to dst switch.
        :param src: source switch
        :param dst: destination switch
        """
        src_mac = self.node_to_node_mac(src, dst)
        dst_mac = self.node_to_node_mac(dst, src)
        egress_port = self.node_to_node_port_num(src, dst)

        # ethernet
        # noinspection PyTypeChecker
        src_bytes = b"".join([codecs.decode(x, 'hex') for x in src_mac.split(":")])
        # noinspection PyTypeChecker
        dst_bytes = b"".join([codecs.decode(x, 'hex') for x in dst_mac.split(":")])

        # probably wrong, dst comes first, but we ignore those fields anyway (for now)
        eth = dst_bytes + src_bytes + struct.pack("!H", 0x1234)

        # heart beat
        heartbeat = egress_port << 7 | (1 << 6)  # port | cpu_bit
        heartbeat = struct.pack("!H", heartbeat)
        heartbeat = eth + heartbeat

        self.sockets[src].send(heartbeat)

        logging.info(f'[heartbeat] sent heartbeat {src}->{dst}')

    def monitor_rates(self) -> bool:
        """
        Collects the bytes / packet counter values from all switches. In case of no change since the last mesaurement,
        a heartbeat is sent out.
        :return:
        """
        should_recompute = False

        for src, dst in self.last_measurements:
            conn = src, dst
            ctrl = self.controllers[dst]

            bytes_count, packet_count = ctrl.counter_read(
                'port_counter',
                self.node_to_node_port_num(dst, src),  # we're looking at the ingress, thus its reversed
            )

            cur = time.time(), bytes_count, packet_count
            self.last_measurements[conn].append(cur)
            self.last_measurements[conn] = self.last_measurements[conn][-BUFFER_SIZE:]
            if len(self.last_measurements[conn]) < BUFFER_SIZE:
                # only start making decisions once our buffer is filled
                self.send_heartbeat(src, dst)
                continue

            diff_lg = tuple(map(operator.sub, cur, self.last_measurements[conn][-3]))
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
        """
        Mark link between src and dst as up.
        :param src: Source switch
        :param dst: Destination switch
        """
        logging.info(f'[link] {src}->{dst} is up')
        self.set_link(src, dst, up=True)

    def set_link_down(self, src, dst):
        """
        Mark link between src and dst as down.
        :param src: Source switch
        :param dst: Destination switch
        """
        logging.info(f'[link] {src}->{dst} is down')
        self.set_link(src, dst, up=False)

    def set_link(self, src, dst, up: True):
        """
        Change link state of link. Do not use directly, instead use set_link_{up, down}.
        :param src: Source switch
        :param dst: Destination switch
        :param up: Whether to mark the link as up or down
        """
        self.links[(src, dst)] = up
        self.controllers[src].register_write(
            register_name='link_state',
            index=self.node_to_node_port_num(src, dst),
            value=1 if up else 0,
        )

        if up:
            self.graph.add_edge(src, dst)
        else:
            if self.graph.has_edge(src, dst):
                self.graph.remove_edge(src, dst)

    ####################
    # Path computation #
    ####################

    def recompute_weights(self):
        """Recompute all capacity and weight values in self.graph."""
        for src, dst in itertools.permutations(self.switches(), 2):
            if self.graph.has_edge(src, dst):
                capacity = round((10.0 * 2 ** 20 - self.get_bandwidth(src, dst)[0] * 8) / 2 ** 20)
                self.graph[src][dst]['capacity'] = max(capacity, 1)
                self.graph[src][dst]['weight'] = self.topology[src][dst]['delay'] + 1

    def recompute_paths(self):
        """Recomputes all paths and registers them to the switches. Expensive operation."""
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

    def get_paths_between_filtered(self, classification: Classification, src: str, dst: str,
                                   via: typing.Optional[str] = None, k: int = 8) -> typing.List[Selection]:
        """
        Wrapper for self.get_paths_between that filters invalid paths and sorts it based on selection.multiplier.
        """
        paths = self.get_paths_between(classification, src, dst, via, k)
        paths = filter(lambda path: len(path.path) <= MAX_PATH_LENGTH, paths)
        paths = sorted(paths)
        paths = list(paths)

        if len(paths) == 0:
            log = f'no paths found between {src} and {dst}'
            if via is not None:
                log = f'{log} via {via}'

            raise Exception(log)

        return list(itertools.islice(paths, k))

    def get_paths_between(self, classification: Classification, src: str, dst: str, via: typing.Optional[str] = None,
                          k: int = 8):
        """
        Compute optimal paths based on classification.
        :param classification: Whether to optimize for TCP or UDP traffic.
        :param src: Source switch
        :param dst: Destination switch
        :param via: Via switch (optional)
        :param k: Maximum number of paths
        :return: List of optimal selection of paths
        """
        if via is None:
            if classification is Classification.TCP:
                paths, capacities = self.compute_best_flows(src, dst)

                return [Selection(path=x[0], multiplier=x[1]) for x in zip(paths, capacities)]
            elif classification is Classification.UDP:
                paths = list(itertools.islice(nx.shortest_simple_paths(self.graph, src, dst), k * 2))
                max_weight = nx.path_weight(self.graph, paths[0], weight='weight') * DELAY_MULTIPLIER_THRESHOLD
                paths = filter(lambda path: self.path_weight(path) <= max_weight, paths)
                paths = sorted(paths, key=self.path_weight)
                paths = list(itertools.islice(paths, k))

                def multiplier(path):
                    return 1 / (self.path_weight(path) ** 3)

                return [Selection(path=path, multiplier=multiplier(path)) for path in paths]
            else:
                raise Exception(f'invalid classification "{classification.name}"')

        first_paths = self.extract_paths((self.get_paths_between(classification, src, via, k=k)))
        second_paths = self.extract_paths((self.get_paths_between(classification, via, dst, k=k)))
        paths = [
            [*first_path, *second_path[1:]]
            for first_path in first_paths
            for second_path in second_paths
        ]

        return [Selection(path=path, multiplier=1) for path in paths]

    def compute_remaining_flow(self, src: str, residual: typing.Dict[str, typing.Dict[str, int]]) \
            -> typing.List[typing.List[str]]:
        """Compute list of paths (flows) that are part of the residual flow.
        :param src: Starting node
        :param residual: Map with residual values
        :return: List of paths starting from src
        """
        flows = []
        for next_hop, flow in residual[src].items():
            if flow == 0:
                continue

            remaining = self.compute_remaining_flow(next_hop, residual)

            flows.extend([[src] + rest_path for rest_path in remaining])

        return flows if len(flows) > 0 else [[src]]

    def compute_best_flows(self, src: str, dst: str) -> (typing.List[typing.List], typing.List[int]):
        """
        Compute the best paths based on max-flow computation.
        :param src: Source switch
        :param dst: Destination switch
        :return: List of paths and a corresponding list containing the capacity (available bandwidth) of each path
        """
        residual = nx.max_flow_min_cost(self.graph, src, dst)
        flows = self.compute_remaining_flow(src, residual)

        for flow in flows:
            if flow[-1] != dst:
                logging.warning(f'flow {src}->{dst} not complete ({flow})')

        flows = list(filter(lambda x: x[-1] == dst, flows))
        if len(flows) == 0:
            return [], []

        def path_capacity(path: typing.List[str]):
            cur_capacity = INFINITY
            for _src, _dst in pairwise(path):
                cur_capacity = min(cur_capacity, residual[_src][_dst])

            if cur_capacity == INFINITY:
                raise Exception('invalid capacity')

            return cur_capacity

        zipped = zip(flows, map(path_capacity, flows))
        zipped = sorted(zipped, key=lambda x: x[1], reverse=True)
        return list(zip(*zipped))

    @staticmethod
    def path_capacity(residual, path: typing.List[str]) -> int:
        """
        Compute the capacity (available bandwidth) of a path
        :param residual: Map with residual values
        :param path: Path for which the capacity should be computed
        :return: Capacity (available bandwidth) for the path
        """
        cur_capacity = INFINITY
        for src, dst in pairwise(path):
            cur_capacity = min(cur_capacity, residual[src][dst])

        if cur_capacity == INFINITY:
            raise Exception('invalid capacity')

        return cur_capacity

    @staticmethod
    def extract_paths(selections: typing.List[Selection]) -> typing.List[typing.List[str]]:
        """
        Return just the list with paths from a list of selections
        :param selections: List of selections
        :return: List of paths
        """
        return [selection.path for selection in selections]

    def register_paths(self, src: str, dst: str, selections: typing.List[Selection], classification: Classification):
        """
        Registers a selection of paths on the switches, based on their multiplier factor
        :param src: Source switch
        :param dst: Destination switch
        :param selections: List of selections
        :param classification: Classification.{TCP, UDP}
        """
        selections = sorted(selections)
        total_multiplier = sum(map(lambda x: x.multiplier, selections))
        for selection in selections[:-1]:
            selection.multiplier /= total_multiplier
            selection.multiplier *= PATH_VARIATION
            selection.multiplier = round(selection.multiplier)
        selections[-1].multiplier = PATH_VARIATION - sum(map(lambda x: x.multiplier, selections[:-1]))

        for selection in selections:
            logging.info(f'[path] {classification.name} {src}->{dst}: {selection}')

        idx = 0
        for selection in selections:
            for host in self.get_hosts_connected_to(dst):
                egress_list_encoded, egress_list_count = self.get_encoded_egress(selection.path, host)
                host_ip = self.get_host_ip_with_subnet(host)

                self.controllers[src].table_add(
                    table_name='path_state',
                    action_name='do_nothing',
                    match_keys=[egress_list_encoded],
                    action_params=[],
                )

                for _ in range(selection.multiplier):
                    self.controllers[src].table_add(
                        table_name='forwarding_table',
                        action_name='set_path',
                        match_keys=[host_ip, str(idx), str(classification.value)],
                        action_params=[egress_list_encoded, str(egress_list_count)]
                    )

                    idx += 1

    def run(self):
        """Let's go!"""
        self.connect_to_switches()
        self.connect_to_sockets()
        self.reset_states()
        self.initialize_link_monitoring()
        self.initialize_meters()
        self.initialize_registers()
        self.install_macs()

        time_function(self.recompute_weights)
        time_function(self.compute_alternative_paths)
        time_function(self.recompute_paths)

        last_monitor = time.time()
        last_recomputation = time.time()

        def recompute():
            nonlocal last_recomputation

            should_recompute = time_function(self.monitor_rates)
            if time.time() - last_recomputation > MAX_RECOMPUTATION:
                should_recompute = True

            if should_recompute:
                time_function(self.recompute_weights)
                time_function(self.recompute_paths)
                last_recomputation = time.time()

        while True:
            time.sleep(max(last_monitor + MIN_MONITOR_WAIT - time.time(), 0))
            last_monitor = time.time()

            time_function(recompute)


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
        base_traffic_path=args.base_traffic,
        mock=args.mock,
        slas_path=args.slas,
    )

    controller.run()
