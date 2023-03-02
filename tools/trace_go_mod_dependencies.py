#!/usr/bin/env python
# This tool finds what direct dependencies caused the given inderect dependency


import argparse
import subprocess

import networkx as nx

g = nx.DiGraph()


def get_top_module(dir=None):
    return subprocess.check_output('grep "^module" go.mod | cut -d" " -f2', shell=True, cwd=dir).decode("utf-8")


def find_root(G, child):
    parent = list(G.predecessors(child))
    if len(parent) == 0:
        print(f"found root: {child}")
        return child
    return find_root(G, parent[0])


def get_mod_deps(top_module, package, dir=None, display_graph=False):
    main_deps = set()
    output = subprocess.check_output("go mod graph", shell=True, cwd=dir)
    for line in output.decode("utf-8").removesuffix("\n").split("\n"):
        dep = line.split(" ")
        if dep[0].strip() == top_module:
            main_deps.add(dep[1])
        else:
            g.add_edge(dep[0], dep[1])

    graph = nx.dfs_tree(g.reverse(), source=package).reverse()

    if not display_graph:
        for n in graph.nodes():
            if n in main_deps:
                print(n)
    else:
        nx.draw_networkx(graph)
        import matplotlib.pyplot as plt

        plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--package", required=True, help="Package to search")
    parser.add_argument("-d", "--dir", required=False, help="Package to search")
    parser.add_argument("-g", "--display-graph", action="store_true", help="Package to search")

    args = parser.parse_args()

    top_module = get_top_module(args.dir).strip()
    get_mod_deps(top_module, package=args.package, dir=args.dir, display_graph=args.display_graph)
