## What is this?
We tackled this project for the course [Advanced Topics in 
Communication Networks](https://adv-net.ethz.ch) to gain experience in programming switches and optimizing software-defined networks. The poster that gives a good overview on our implementation can be found [here](poster/09_kahn.pdf).

## Group info

| Group name | Oh nein, Kahn! |
| --- | --- |
| Member 1 | [Maša Nešić](https://github.com/MashaNes) |
| Member 2 | [Alkinoos Sarioglou](https://github.com/alksarioglou) |
| Member 3 | [Elwin Stephan](https://github.com/elwin) |

## Overview

We use a novel technique inspired by MPLS and the SCION network: The source switch determines the path for the packet
and writes it to the header. The following switches will look at the determined path and forward the packet accordingly.
This way, we allow for arbitrary path combinations (including loops) and perform atomic updates for paths.

We monitor the bandwidth of all links every 50ms. If no traffic is detected, we send heartbeats and mark the link as
down if they do not arrive. This way, we detect link failures in ca. 100ms.

Paths are computed on the controller, based on bandwidth metrics and link failures. Periodically or after a link
failure, they are pushed to the switches. This process takes ca. 2 seconds. To react faster to link failures, we
pre-compute alternative paths on each switch to all destinations, for each outgoing link that could fail. This allows to
use an alternative path (that might not be globally optimal) within 100ms.

We load-balance by keeping a set of multiple paths for each source/destination pair, one of which is randomly selected 
(with a probability dependent on how optimal it is) on a per-packet (UDP) or per-flowlet (TCP) basis.

The paths for UDP are computed by minimizing for delay and hop count. For TCP, paths are computed by maximizing for
available bandwidth.

Rate-limiting allows peak 1.75 Mbps for UDP flows of each port range (committed 0.875 Mbps). For yellow meter color, we drop
the packet with a probability of 30% and for red, we drop every time.

## Individual Contributions

### Maša Nešić

Brought food and kept the team happy, helped bridge the gap between the controller world and the data plane. Also
contributed the idea of load balancing algorithm and buffer acceptance (was very sad that queues don't work in this
architecture), poster creator.

### Alkinoos Sarioglou

Kept saying "grüezi mitenand" and provided good music for the background. Also fought the fight with P4 and won!
Contributed to solving the problem of traffic engineering by rate limiting UDP traffic.

### Elwin Stephan

A master in git, lost a day's work in code by showing off. Also wrote some controller code, contributed the idea for
storing the path segments in the header and the idea to statically compute a number of best paths per (source,
destination) pair.
