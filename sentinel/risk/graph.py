"""A lightweight entity relationship graph (adjacency lists, in memory) with
**time-aware edges**.

    customer -OWNS-> account -USES-> device            (ts: first use / registration)
    account -MADE-> transaction -PAID-> merchant       (ts: transaction time)
    merchant -OWNED_BY-> owner ; merchant -HOSTS-> domain   (static)
    account -HAS-> instrument                           (ts: instrument added)
    account -TRANSFERRED_TO-> account                   (ts: transfer time)
    ip -ORIGINATES-> session -ON-> account              (ts: session start)

Every edge may carry the ISO-8601 timestamp at which the relationship came
into existence. Queries take an optional ``as_of``: an edge is visible at
``as_of`` when it has no timestamp (a static relationship) or its timestamp is
``<= as_of``. That is what lets entity profiles and monitoring features be
computed as they *would have been* at the moment of the event being scored,
instead of with today's graph -- the point-in-time discipline the risk engine
depends on. Cycle search additionally takes a ``[since, until]`` window so a
"circular transfer" means money moving in a circle *within the monitoring
window*, not two unrelated transfers months apart.

Every edge is stored in both directions so questions like "what accounts share
this device?" are one hop. No graph database: the whole thing is a dict, which
is honest for the portfolio scale and trivially replayable. Timestamps are
compared as strings, which is exact for the canonical ``YYYY-MM-DDTHH:MM:SS``
form every record in the platform uses.
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
    ts: str | None = None  # when the relationship came into existence; None = static


def _visible(e: Edge, as_of: str | None) -> bool:
    return e.ts is None or as_of is None or e.ts <= as_of


def _in_window(e: Edge, since: str | None, until: str | None) -> bool:
    if e.ts is None:
        return True  # a static relationship is always in the window
    if since is not None and e.ts < since:
        return False
    return until is None or e.ts <= until


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

    def add_edge(self, src: Node, dst: Node, rel: str, ts: str | None = None) -> None:
        self._adj.setdefault(src, []).append(Edge(src, dst, rel, ts))
        self._adj.setdefault(dst, []).append(Edge(dst, src, f"~{rel}", ts))
        self._attrs.setdefault(src, {})
        self._attrs.setdefault(dst, {})

    def link(self, sk: str, sid: str, rel: str, dk: str, did: str, ts: str | None = None) -> None:
        self.add_edge(self.add_node(sk, sid), self.add_node(dk, did), rel, ts)

    # ---- queries ----------------------------------------------------------------
    def has(self, kind: str, id: str) -> bool:
        return Node(kind, id) in self._adj

    def attrs(self, node: Node) -> dict[str, object]:
        return self._attrs.get(node, {})

    def neighbors(
        self,
        node: Node,
        rel: str | None = None,
        kind: str | None = None,
        as_of: str | None = None,
    ) -> list[Node]:
        out = []
        for e in self._adj.get(node, ()):
            if rel is not None and e.rel != rel:
                continue
            if kind is not None and e.dst.kind != kind:
                continue
            if not _visible(e, as_of):
                continue
            out.append(e.dst)
        return sorted(set(out))

    def first_ts(self, src: Node, dst: Node, rel: str) -> str | None:
        """Earliest timestamp of ``rel`` edges from ``src`` to ``dst``; ``None`` when
        no such edge exists or when a static (timeless) edge exists."""
        found = False
        best: str | None = None
        for e in self._adj.get(src, ()):
            if e.dst == dst and e.rel == rel:
                found = True
                if e.ts is None:
                    return None
                best = e.ts if best is None or e.ts < best else best
        return best if found else None

    def accounts_sharing_device(self, device_id: str, as_of: str | None = None) -> list[str]:
        return [n.id for n in self.neighbors(Node("device", device_id), "~USES", "account", as_of)]

    def devices_for_account(self, account_id: str, as_of: str | None = None) -> list[str]:
        return [n.id for n in self.neighbors(Node("account", account_id), "USES", "device", as_of)]

    def device_first_used(self, account_id: str, device_id: str) -> str | None:
        """When this device was first seen on this account (registration or first
        transaction). ``None`` if the pair has no edge at all."""
        return self.first_ts(Node("account", account_id), Node("device", device_id), "USES")

    def device_known(self, account_id: str, device_id: str) -> bool:
        return Node("device", device_id) in {
            e.dst for e in self._adj.get(Node("account", account_id), ()) if e.rel == "USES"
        }

    def merchants_for_owner(self, owner_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("owner", owner_id), "~OWNED_BY", "merchant")]

    def transactions_for_account(self, account_id: str, as_of: str | None = None) -> list[str]:
        return [
            n.id for n in self.neighbors(Node("account", account_id), "MADE", "transaction", as_of)
        ]

    def accounts_for_customer(self, customer_id: str) -> list[str]:
        return [n.id for n in self.neighbors(Node("customer", customer_id), "OWNS", "account")]

    def accounts_sharing_instrument(
        self, instrument_id: str, as_of: str | None = None
    ) -> list[str]:
        return [
            n.id
            for n in self.neighbors(Node("instrument", instrument_id), "~HAS", "account", as_of)
        ]

    def instruments_for_account(self, account_id: str, as_of: str | None = None) -> list[str]:
        return [
            n.id for n in self.neighbors(Node("account", account_id), "HAS", "instrument", as_of)
        ]

    def entities_for_device(self, device_id: str) -> list[Node]:
        return self.neighbors(Node("device", device_id))

    def linked_accounts(self, account_id: str, as_of: str | None = None) -> set[str]:
        """Accounts reachable through a shared device or shared instrument, as of a time."""
        me = Node("account", account_id)
        out: set[str] = set()
        for dev in self.neighbors(me, "USES", "device", as_of):
            out.update(self.accounts_sharing_device(dev.id, as_of))
        for ins in self.neighbors(me, "HAS", "instrument", as_of):
            out.update(self.accounts_sharing_instrument(ins.id, as_of))
        out.discard(account_id)
        return out

    def neighborhood(
        self, node: Node, depth: int = 2, limit: int = 200
    ) -> tuple[list[Node], list[Edge]]:
        """Breadth-first neighbourhood for visualisation (current graph, no as_of)."""
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
                    edges.append(Edge(e.dst, cur, e.rel[1:], e.ts))
                    q.append((e.dst, d + 1))
        return sorted(seen), edges

    def find_cycles_from(
        self,
        start: Node,
        rel: str,
        max_len: int = 5,
        *,
        since: str | None = None,
        until: str | None = None,
    ) -> list[list[Node]]:
        """Simple cycles through ``start`` following ``rel`` edges whose timestamps
        fall inside ``[since, until]`` (static edges always qualify). Deterministic:
        adjacency order is insertion order and the result is sorted."""
        cycles: list[list[Node]] = []

        def dfs(cur: Node, path: list[Node]) -> None:
            if len(path) > max_len:
                return
            for e in self._adj.get(cur, ()):
                if e.rel != rel or not _in_window(e, since, until):
                    continue
                if e.dst == start and len(path) >= 2:
                    cycles.append(path + [start])
                elif e.dst not in path:
                    dfs(e.dst, path + [e.dst])

        dfs(start, [start])
        uniq = {tuple(c) for c in cycles}
        return [list(c) for c in sorted(uniq, key=lambda c: (len(c), [n.key for n in c]))]

    @property
    def node_count(self) -> int:
        return len(self._adj)

    @property
    def edge_count(self) -> int:
        return sum(1 for edges in self._adj.values() for e in edges if not e.rel.startswith("~"))

    def to_dict(self, node: Node, depth: int = 2, max_nodes: int = 80) -> dict[str, object]:
        """Serialise the ``depth``-hop neighbourhood for the console. Large
        neighbourhoods are bounded to ``max_nodes``: the root and structural
        entities (accounts, devices, instruments, merchants, customers, owners)
        are kept before event nodes (transactions, sessions), so the picture that
        survives truncation is the relationship structure, not the traffic."""
        all_nodes, all_edges = self.neighborhood(node, depth)
        total = len(all_nodes)
        truncated = total > max_nodes
        if truncated:
            event_kinds = {"transaction", "session"}
            ranked = sorted(
                all_nodes,
                key=lambda n: (n != node, n.kind in event_kinds, n.key),
            )
            keep = set(ranked[:max_nodes])
            nodes = [n for n in all_nodes if n in keep]
            edges = [e for e in all_edges if e.src in keep and e.dst in keep]
        else:
            nodes, edges = all_nodes, all_edges
        return {
            "root": node.key,
            "total_nodes": total,
            "truncated": truncated,
            "nodes": [
                {
                    "key": n.key,
                    "kind": n.kind,
                    "id": n.id,
                    **{k: v for k, v in self.attrs(n).items()},
                }
                for n in nodes
            ],
            "edges": [
                {"src": e.src.key, "dst": e.dst.key, "rel": e.rel, **({"ts": e.ts} if e.ts else {})}
                for e in edges
            ],
        }
