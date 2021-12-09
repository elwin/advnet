import argparse
import codecs
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


class Controller(object):

    def __init__(self, base_traffic, mock: bool):
        self.mock = mock
        self.base_traffic_file = base_traffic
        self.topology = self.load_topology()
        self.controllers: typing.Dict[str, SmartSwitch] = {}
        self.sockets: typing.Dict[str, socket.socket] = {}
        self.links: typing.Dict[typing.Tuple[str, str], bool] = {}
        self.last_measurements: typing.Dict[typing.Tuple, typing.List] = {}
        self.old_paths = []
        self.new_paths = []

    def compute_weight(self, src: str, dst: str):
        if not self.links[(src, dst)]:
            return INFINITY

        edge = self.topology[src][dst]
        bw_bytes, _ = self.get_bandwidth(src, dst)
        delay = edge['delay']
        congestion_ratio = bw_bytes / (10 * 2 ** 10)

        return delay + 20 * congestion_ratio ** 2
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

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.connect_to_sockets()
        self.reset_states()
        self.set_links()

    def reset_states(self):
        """Resets switches state"""
        [ctrl.reset_state() for ctrl in self.controllers.values()]

    def set_links(self):
        for src, dst in itertools.permutations(self.switches(), 2):
            if not self.topology.are_neighbors(src, dst):
                continue

            self.set_link_up(src, dst)
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
        self.run()
        logging.info('[info] run completed')

        added_paths = set(map(tuple, self.new_paths)) - set(map(tuple, self.old_paths))
        deleted_paths = set(map(tuple, self.old_paths)) - set(map(tuple, self.new_paths))

        for path in sorted(list(map(list, added_paths))):
            logging.info(f'[path] added {path}')

        for path in sorted(list(map(list, deleted_paths))):
            logging.info(f'[path] removed {path}')

    def run(self):
        switches = self.switches()
        self.install_macs()
        for ctrl in self.controllers.values():
            ctrl.table_set_default("ipv4_lpm", "drop")
            ctrl.table_set_default("ecmp_group_to_nhop", "drop")

        # Add table entries for directly connected hosts
        for switch in switches:
            ctrl = self.controllers[switch]

            for host in self.topology.get_hosts_connected_to(switch):
                host_ip = self.get_host_ip_with_subnet(host)
                next_hop_mac = self.topology.get_host_mac(host)
                host_port = self.get_egress_port(switch, host)
                ctrl.table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [next_hop_mac, str(host_port)])

        best_paths: typing.Dict[typing.Tuple[str, str], typing.List] = {}
        for src, dst in itertools.permutations(self.switches(), 2):
            best_paths[src, dst] = self.topology.get_shortest_paths_between_nodes(src, dst)

        for src_switch in switches:
            for ecmp_group, dst_switch in enumerate(switches):
                if src_switch == dst_switch:
                    continue

                ctrl = self.controllers[src_switch]
                paths = best_paths[src_switch, dst_switch]

                self.new_paths.extend(paths)

                if len(paths) == 0:
                    raise Exception(f'no paths found between {src_switch} and {dst_switch}')
                elif len(paths) == 1:
                    path = paths[0]
                    next_hop = path[1]
                    next_hop_mac = self.topology.node_to_node_mac(src_switch, next_hop)
                    next_hop_egress = self.get_egress_port(src_switch, next_hop)

                    for host in self.topology.get_hosts_connected_to(dst_switch):
                        host_ip = self.get_host_ip_with_subnet(host)

                        ctrl.table_add("ipv4_lpm", "set_nhop", [host_ip], [next_hop_mac, str(next_hop_egress)])

                else:
                    for host in self.topology.get_hosts_connected_to(dst_switch):
                        host_ip = self.get_host_ip_with_subnet(host)

                        ctrl.table_add("ipv4_lpm", "ecmp_group", [host_ip], [str(ecmp_group), str(len(paths))])

                    for i, path in enumerate(paths):
                        next_hop = path[1]
                        next_hop_egress = self.get_egress_port(src_switch, next_hop)
                        next_hop_mac = self.topology.node_to_node_mac(src_switch, next_hop)

                        ctrl.table_add(
                            "ecmp_group_to_nhop",
                            "set_nhop",
                            [str(ecmp_group), str(i)],
                            [next_hop_mac, str(next_hop_egress)],
                        )

        for (src, dst), cur_best_paths in best_paths.items():
            for best_path in cur_best_paths:
                best_next_hop = best_path[1]
                best_next_egress = self.get_egress_port(src, best_next_hop)

                for alt_next_hop in self.topology.neighbors(src):
                    if not self.topology.isSwitch(alt_next_hop):
                        continue

                    if alt_next_hop == dst:
                        continue

                    if alt_next_hop == best_next_hop:
                        continue

                    if src in best_paths[alt_next_hop, dst]:
                        continue

                    alt_next_egress = self.get_egress_port(src, alt_next_hop)
                    alt_next_mac = self.topology.node_to_node_mac(src, alt_next_hop)

                    for host in self.topology.get_hosts_connected_to(dst):
                        host_ip = self.get_host_ip_with_subnet(host)

                        self.controllers[src].table_add(
                            table_name='find_lfa',
                            action_name='set_nhop',
                            match_keys=[str(best_next_egress), host_ip],
                            action_params=[alt_next_mac, str(alt_next_egress)]
                        )

                    break

        for switch in switches:
            ctrl = self.controllers[switch]
            ctrl.apply()

    @staticmethod
    def node_in_any_path(node, paths: typing.List[typing.List[str]]) -> bool:
        for path in paths:
            if node in path:
                return True

        return False

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
        """Main function"""
        switches = self.switches()

        for src in switches:
            ctrl = self.controllers[src]

            for index in range(1024):
                ctrl.register_write("known_flows_egress", index, 0)
                ctrl.register_write("flowlet_time_stamp", index, 0)
            print("Register for ports has been reset.")
        self.recompute()

        last_recomputation = time.time()
        while not time.sleep(0.25):
            should_recompute = self.monitor_rates()
            if time.time() - last_recomputation > 5:
                should_recompute = True

            if should_recompute:
                last_recomputation = time.time()
                self.recompute()

        time.sleep(120)


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
    controller = Controller(args.base_traffic, args.mock)
    controller.init()
    controller.main()
