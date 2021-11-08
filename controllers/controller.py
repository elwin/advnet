"""Template of an empty global controller"""

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

class RoutingController(object):

    def __init__(self):
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.init()

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def run(self):
        """Run function"""

    def main(self):
        """Main function"""
        self.run()


if __name__ == "__main__":
    controller = RoutingController().main()
