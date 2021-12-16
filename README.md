## Group info

| Group name | O nein, Kahn! |  |  |
| --- | --- | --- | --- |
| Member 1 | Maša Nešić | mnesic | mnesic@ethz.ch |
| Member 2 | Alkinoos Sarioglou | asarioglou | asarioglou@ethz.ch |
| Member 3 | Elwin Stephan | stephael | stephael@ethz.ch |

## Overview

For our implementation, we use a novel technique inspired by MPLS and the SCION network: The first switch at the edge of
the network determines the path for the packet and writes it to the header. The following switches will only look at the
determined path and forward the packet accordingly. With this approach we allow for arbitrary path combinations,
including loops and perform atomic updates for paths.

We monitor the bandwidth of all links every 50ms. If no traffic is detected, we send heartbeats and mark the link as
down should they not arrive. With this approach, we're able to detect link failures in about 100ms.

Paths are computed on the controller, based on the collected bandwidth metrics and link failures. Periodically (or
immediately after a link) failure, they are pushed to the switches. This process takes around 2 seconds. To react faster
to link failures, we pre-compute alternative paths on each switch to all destinations, for each outgoing link that could
fail. This allows us to switch to an alternative path (that might not be globally optimal) within 100ms.

Load balancing happens by keeping a set of multiple paths for each source/destination pair, one of which is randomly
selected on a per-packet (UDP) or per-flowlet (TCP) basis.

The paths for UDP are computed by minimizing for delay and hop count. For TCP, paths are computed by maximizing for
available bandwidth.

## Individual Contributions

In this section, note down 1 or 2 sentences *per team member* outlining everyone's contribution to the project. We want
to see that everybody contributed, but you don't need to get into fine details. For example, write who contributed to
which feature of your solution, but do *not* write who implemented a particular function.

### Maša Nešić

Brought food and kept the team happy, helped bridge the gap between the controller world and the data plane.
Also contributed the idea of load balancing algorithm and buffer acceptance (was very sad that queues don't work in this
architecture).

### Alkinoos Sarioglou

Kept saying "grüezi mitenand" and provided good music for the background.
But also fought the fight against P4 and won! Contributed to solving the problem of traffic engineering by rate limiting
UDP traffic.

### Elwin Stephan

A master in git, lost a day's work in code by showing off.
But also mainly wrote controller code, contributed the idea for storing the path segments in the header and the idea
to statically compute a number of best paths per (source, destination) pair.