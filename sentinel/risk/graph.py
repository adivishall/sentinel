"""A lightweight entity relationship graph (adjacency lists, in memory).

    customer -OWNS-> account -USES-> device
    account -MADE-> transaction -PAID-> merchant -OWNED_BY-> owner
    merchant -HOSTS-> domain ; account -HAS-> instrument ; ip -ORIGINATES-> session -ON-> account

Every edge is stored in both directions so questions like "what accounts share
this device?" are one hop. No graph database: the whole thing is a dict, which
is honest for the portfolio scale and trivially replayable.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass(frozen=True, order=True)
class Node:
    kind: str
    id: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.id}"


@dataclass(frozen=True)
class Edge:
    src: Node
    dst: Node
    rel: str


@dataclass
class EntityGraph:
    _adj: dict[Node, list[Edge]] = field(default_factory=lambda: defaultdict(list))
    _attrs: dict[Node, dict[str, object]] = field(default_factory=dict)

    # ---- construction ---------------------------------------------------------
    def add_node(self, kind: str, id: str, **attrs: object) -> Node:
        n = Node(kind, id)
        self._attrs.setdefault(n, {}).update(attrs)
        self._adj.setdefault(n, [])
        return n

    def add_edge(self, src: Node, dst: Node, rel: str) -> None:
        self._adj.setdefault(src, []).append(Edge(src, dst, rel))
        self._adj.setdefault(dst, []).append(Edge(dst, src, f"~{rel}"))
        self._attrs.setdefault(src, {})
        self._attrs.setdefault(dst, {})

    def link(self, sk: str, sid: str, rel: str, dk: str, did: str) -> None:
        self.add_edge(self.add_node(sk, sid), self.add_node(dk, did), rel)

    # ---- queries ----------------------------------------------------------------
    def has(self, kind: str, id: str) -> bool:
        return Node(kind, id) in self._adj

    def attrs(self, node: Node) -> dict[str, object]:
        return self._attrs.get(node, {})

    def neighbors(self, node: Node, rel: str | None = None, kind: str | None = None) -> list[Node]:
        out = []
        for e in self._adj.get(node, ()):
            if rel is not None and e.rel != rel:
                continue
            if kind is not None and e.dst.kind != kind:
                continue
            out.append(e.dst)
        return sorted(set(out))

    def accounts_sharing_device(self, device_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("device", device_id), "~USES", "account")]

    def devices_for_account(self, account_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("account", account_id), "USES", "device")]

    def merchants_for_owner(self, owner_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("owner", owner_id), "~OWNED_BY", "merchant")]

    def transactions_for_account(self, account_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("account", account_id), "MADE", "transaction")]

    def accounts_for_customer(self, customer_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("customer", customer_id), "OWNS", "account")]

    def accounts_sharing_instrument(self, instrument_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("instrument", instrument_id), "~HAS", "account")]

    def entities_for_device(self, device_id: str) -> list[Node]:
        return self.neighbors(Node("device", device_id))

    def linked_accounts(self, account_id: str) -> set[str]:
        """Accounts reachable through a shared device or shared instrument."""
        me = Node("account", account_id)
        out: set[str] = set()
        for dev in self.neighbors(me, "USES", "device"):
            out.update(self.accounts_sharing_device(dev.id))
        for ins in self.neighbors(me, "HAS", "instrument"):
            out.update(self.accounts_sharing_instrument(ins.id))
        out.discard(account_id)
        return out

    def neighborhood(
        self, node: Node, depth: int = 2, limit: int = 200
    ) -> tuple[list[Node], list[Edge]]:
        """Breadth-first neighbourhood for visualisation."""
        seen = {node}
        q: deque[tuple[Node, int]] = deque([(node, 0)])
        edges: list[Edge] = []
        while q and len(seen) < limit:
            cur, d = q.popleft()
            if d >= depth:
                continue
            for e in self._adj.get(cur, ()):
                if e.rel.startswith("~"):
                    continue
                edges.append(e)
                if e.dst not in seen:
                    seen.add(e.dst)
                    q.append((e.dst, d + 1))
            for e in self._adj.get(cur, ()):
                if not e.rel.startswith("~"):
                    continue
                if e.dst not in seen and len(seen) < limit:
                    seen.add(e.dst)
                    edges.append(Edge(e.dst, cur, e.rel[1:]))
                    q.append((e.dst, d + 1))
        return sorted(seen), edges

    def find_cycles_from(self, start: Node, rel: str, max_len: int = 5) -> list[list[Node]]:
        """Simple cycles through ``start`` following ``rel`` edges (for circular transfers)."""
        cycles: list[list[Node]] = []

        def dfs(cur: Node, path: list[Node]) -> None:
            if len(path) > max_len:
                return
            for e in self._adj.get(cur, ()):
                if e.rel != rel:
                    continue
                if e.dst == start and len(path) >= 2:
                    cycles.append(path + [start])
                elif e.dst not in path:
                    dfs(e.dst, path + [e.dst])

        dfs(start, [start])
        return cycles

    @property
    def node_count(self) -> int:
        return len(self._adj)

    @property
    def edge_count(self) -> int:
        return sum(1 for edges in self._adj.values() for e in edges if not e.rel.startswith("~"))

    def to_dict(self, node: Node, depth: int = 2) -> dict[str, object]:
        nodes, edges = self.neighborhood(node, depth)
        return {
            "root": node.key,
            "nodes": [
                {
                    "key": n.key,
                    "kind": n.kind,
                    "id": n.id,
                    **{k: v for k, v in self.attrs(n).items()},
                }
                for n in nodes
            ],
            "edges": [{"src": e.src.key, "dst": e.dst.key, "rel": e.rel} for e in edges],
        }
