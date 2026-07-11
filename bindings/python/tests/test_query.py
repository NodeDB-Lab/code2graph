# SPDX-License-Identifier: Apache-2.0

import unittest

from code2graph import GraphIndex


def global_id(lang, name):
    return {"version": 1, "scip": f"codegraph . . . {name}.", "lang": lang}


def local_id(file, identifier):
    return {"version": 1, "scip": f"local {identifier}", "file": file}


def symbol(identifier, name, file):
    return {
        "id": identifier,
        "name": name,
        "kind": "Function",
        "visibility": "Public",
        "entry_points": [],
        "file": file,
        "line": 1,
        "span": {"start": 0, "end": 1},
        "signature": f"fn {name}()",
    }


def edge(source, target, byte, role="Call", confidence="Exact", provenance="ScopeGraph"):
    return {
        "from": source,
        "to": target,
        "role": role,
        "confidence": confidence,
        "provenance": provenance,
        "occ": {"file": "src/calls.rs", "line": 1, "col": byte, "byte": byte},
    }


def fixture(reverse_edges=False):
    rust_shared = global_id("rust", "shared")
    python_shared = global_id("python", "shared")
    endpoint = local_id("vendor/a.rs", "remote")
    same_display_endpoint = local_id("vendor/b.rs", "remote")
    caller_a = global_id("rust", "caller_a")
    caller_b = global_id("rust", "caller_b")
    caller_c = global_id("rust", "caller_c")
    ignored = global_id("rust", "ignored")
    weak = global_id("rust", "weak")
    edges = [
        edge(caller_a, endpoint, 10),
        edge(caller_c, endpoint, 20),
        edge(caller_b, caller_a, 30),
        edge(caller_a, caller_b, 40),
        edge(ignored, endpoint, 50, role="Import"),
        edge(weak, endpoint, 60, confidence="NameOnly", provenance="SymbolTable"),
        edge(endpoint, same_display_endpoint, 70),
    ]
    return {
        "ids": {
            "rust_shared": rust_shared,
            "python_shared": python_shared,
            "endpoint": endpoint,
            "same_display_endpoint": same_display_endpoint,
            "caller_a": caller_a,
            "caller_b": caller_b,
            "caller_c": caller_c,
        },
        "graph": {
            "symbols": [
                symbol(rust_shared, "shared", "src/shared.rs"),
                symbol(python_shared, "shared", "src/shared.py"),
            ],
            "edges": list(reversed(edges)) if reverse_edges else edges,
        },
    }


class GraphIndexQueryTests(unittest.TestCase):
    def test_structural_ids_endpoint_traversal_filters_and_bounds(self):
        data = fixture()
        ids = data["ids"]
        index = GraphIndex(data["graph"])

        self.assertEqual(index.symbol(ids["rust_shared"])["id"], ids["rust_shared"])
        self.assertEqual(index.symbol(ids["python_shared"])["id"], ids["python_shared"])
        self.assertIsNone(index.symbol(global_id("go", "shared")))
        self.assertIsNone(index.symbol(ids["endpoint"]))
        self.assertEqual(
            [item["id"] for item in index.symbols_named("shared")],
            [ids["python_shared"], ids["rust_shared"]],
        )
        self.assertEqual(
            index.ids_with_scip(ids["rust_shared"]["scip"]),
            [ids["python_shared"], ids["rust_shared"]],
        )
        self.assertEqual(
            index.ids_with_scip(ids["endpoint"]["scip"]),
            [ids["endpoint"], ids["same_display_endpoint"]],
        )

        self.assertEqual(
            [item["from"] for item in index.incoming(ids["endpoint"], 10)],
            [
                ids["caller_a"],
                ids["caller_c"],
                global_id("rust", "ignored"),
                global_id("rust", "weak"),
            ],
        )
        self.assertEqual(
            [item["to"] for item in index.outgoing(ids["endpoint"], 10)],
            [ids["same_display_endpoint"]],
        )
        self.assertEqual(
            [item["from"] for item in index.incoming(
                ids["endpoint"], 10, "Call", "Exact", "ScopeGraph"
            )],
            [ids["caller_a"], ids["caller_c"]],
        )
        self.assertEqual(
            [item["from"] for item in index.incoming(
                ids["endpoint"], 10, "Import", "Exact", "ScopeGraph"
            )],
            [global_id("rust", "ignored")],
        )

        full_impact = index.impact(ids["endpoint"], 10, 10, "Call", "Exact", "ScopeGraph")
        self.assertFalse(full_impact["truncated"])
        self.assertNotIn("visited", full_impact)
        self.assertEqual(
            [(step["symbol"], step["depth"]) for step in full_impact["steps"]],
            [(ids["caller_a"], 1), (ids["caller_c"], 1), (ids["caller_b"], 2)],
        )
        self.assertEqual(full_impact["steps"][2]["parent"], ids["caller_a"])

        depth_bound = index.impact(ids["endpoint"], 1, 10, "Call", "Exact", "ScopeGraph")
        self.assertTrue(depth_bound["truncated"])
        self.assertEqual(
            [step["symbol"] for step in depth_bound["steps"]],
            [ids["caller_a"], ids["caller_c"]],
        )
        node_bound = index.impact(ids["endpoint"], 10, 1, "Call", "Exact", "ScopeGraph")
        self.assertTrue(node_bound["truncated"])
        self.assertEqual([step["symbol"] for step in node_bound["steps"]], [ids["caller_a"]])

    def test_rejects_lossy_or_malformed_ids_filters_and_zero_limits(self):
        data = fixture()
        ids = data["ids"]
        index = GraphIndex(data["graph"])

        with self.assertRaisesRegex(ValueError, "graph symbols.id must be a lossless SymbolId serde dict"):
            GraphIndex({"symbols": [{"id": ids["rust_shared"]["scip"]}], "edges": []})
        with self.assertRaisesRegex(ValueError, "lossless SymbolId serde dict"):
            index.symbol(ids["rust_shared"]["scip"])
        with self.assertRaisesRegex(ValueError, "SymbolId wire requires lang"):
            index.incoming({"version": 1, "scip": ids["rust_shared"]["scip"]}, 1)
        with self.assertRaisesRegex(ValueError, "limit must be a positive u32"):
            index.incoming(ids["endpoint"], 0)
        with self.assertRaisesRegex(ValueError, "limit must be a positive u32"):
            index.impact(ids["endpoint"], 1, 0)
        with self.assertRaisesRegex(ValueError, "invalid role"):
            index.incoming(ids["endpoint"], 1, "call")
        with self.assertRaisesRegex(ValueError, "invalid min_confidence"):
            index.incoming(ids["endpoint"], 1, None, "exact")
        with self.assertRaisesRegex(ValueError, "invalid provenance"):
            index.incoming(ids["endpoint"], 1, None, None, "scope_graph")

    def test_query_order_is_independent_of_graph_input_order(self):
        first = fixture()
        second = fixture(reverse_edges=True)
        left = GraphIndex(first["graph"])
        right = GraphIndex(second["graph"])
        self.assertEqual(
            left.incoming(first["ids"]["endpoint"], 10, "Call", "Exact", "ScopeGraph"),
            right.incoming(second["ids"]["endpoint"], 10, "Call", "Exact", "ScopeGraph"),
        )
        self.assertEqual(
            left.impact(first["ids"]["endpoint"], 10, 10, "Call", "Exact", "ScopeGraph"),
            right.impact(second["ids"]["endpoint"], 10, 10, "Call", "Exact", "ScopeGraph"),
        )


if __name__ == "__main__":
    unittest.main()
