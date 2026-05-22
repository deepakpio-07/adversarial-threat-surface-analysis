class GraphGenerator:

    def generate_attack_graph(
        self,
        attack_chains
    ):

        graph_path = (
            "reports/attack_graph.dot"
        )

        with open(graph_path, "w") as graph:

            graph.write("digraph AttackGraph {\n")

            graph.write(
                '    rankdir=LR;\n'
            )

            graph.write(
                '    node [shape=box];\n\n'
            )

            node_count = 0

            for chain_data in attack_chains:

                chain = chain_data["chain"]

                steps = chain.split("→")

                previous_node = None

                for step in steps:

                    current_node = (
                        f"node{node_count}"
                    )

                    clean_step = step.strip()

                    graph.write(
                        f'    {current_node} '
                        f'[label="{clean_step}"];\n'
                    )

                    if previous_node:

                        graph.write(
                            f'    {previous_node} '
                            f'-> {current_node};\n'
                        )

                    previous_node = current_node

                    node_count += 1

                graph.write("\n")

            graph.write("}\n")

        print(
            f"\n[+] Attack graph generated: "
            f"{graph_path}"
        )
