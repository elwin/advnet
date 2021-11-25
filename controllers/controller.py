import argparse

from p4utils.utils.helper import load_topo

try:
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ModuleNotFoundError:
    from mock_simple_switch import SimpleSwitchThriftAPI


class Controller(object):

    def __init__(self, base_traffic):
        self.base_traffic_file = base_traffic
        self.topology = load_topo('topology.json')
        self.controllers = {}
        self.init()

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        """Resets switches state"""
        [ctrl.reset_state() for ctrl in self.controllers.values()]

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

    def main(self):
        """Main function"""
        self.run()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic', type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas', type=str, required=False, default='')
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic)
    controller.main()
