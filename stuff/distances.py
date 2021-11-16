import json
from ast import literal_eval as make_tuple
import networkx as nx
import itertools

mapping = {
    "FRA": "Frankfurt",
    "BER": "Berlin",
    "MUN": "Munich",
    "PAR": "Paris",
    "REN": "Rennes",
    "LIL": "Lille",
    "AMS": "Amsterdam",
    "EIN": "Eindhoven",
    "BAR": "Barcelona",
    "MAD": "Madrid",
    "LIS": "Lisbon",
    "POR": "Porto",
    "LON": "London",
    "MAN": "Manchester",
    "GLO": "Gloucester",
    "BRI": "Bristol",
}

cities = mapping.values()


def main():
    g = nx.Graph()

    with open('../topology/cities.txt') as f:
        for line in f:
            g.add_node(line.strip())

    with open('../topology/links.txt') as f:
        for line in f:
            line = line.split()
            s, t, c = mapping[line[0]], mapping[line[1]], line[2]
            g.add_edge(s, t)

    g.add_edge("Porto", "Frankfurt")
    g.add_edge("Madrid", "Paris")
    g.add_edge("Gloucester", "Paris")

    print('Number of hops:')
    pairs = dict(nx.all_pairs_dijkstra_path_length(g))
    for src, dst in itertools.combinations(cities, 2):
        dist = pairs[src][dst]
        if dist > 3:
            print(f'{src} - {dst}: {dist}')
    print()

    with open('../topology/city_distances.json') as f:
        distances = json.load(f)
        for link, distance in distances.items():
            link = make_tuple(link)
            src, dst = link[0], link[1]

            if src in g and dst in g[src]:
                g[src][dst]['weight'] = round(distance / 250) * 2.5

    distances_sorted = {}
    distances = dict(nx.all_pairs_dijkstra_path_length(g))
    for src, dst in itertools.combinations(cities, 2):
        distances_sorted[(src, dst)] = distances[src][dst]

    print('Delays:')
    for (src, dst), v in sorted(distances_sorted.items(), key=lambda item: -item[1]):
        print(f'{src} - {dst}: {v}')
    print()

    print('Disjoint Paths:')
    for src, dst in itertools.combinations(cities, 2):
        paths = len(list(nx.edge_disjoint_paths(g, src, dst)))
        if paths == 1 \
                and len(list(nx.neighbors(g, src))) > 1 \
                and len(list(nx.neighbors(g, dst))) > 1:
            print(f'{src} - {dst}: {paths}')
    print()

    link_usage = {}
    for src, dst in itertools.combinations(cities, 2):
        hop_src = src
        for hop_dst in nx.shortest_path(g, src, dst):
            if hop_src == hop_dst:
                continue

            link = hop_src, hop_dst
            if hop_src > hop_dst:
                link = hop_dst, hop_src

            if link not in link_usage:
                link_usage[link] = 1
            else:
                link_usage[link] += 1
            hop_src = hop_dst

    print("Link usage:")
    for (src, dst), v in sorted(link_usage.items(), key=lambda item: -item[1]):
        print(f'{src} - {dst}: {v}')


if __name__ == '__main__':
    main()
