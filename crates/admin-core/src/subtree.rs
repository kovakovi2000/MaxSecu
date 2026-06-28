//! Grant-graph subtree revocation, sourced from the **external sink** (DESIGN
//! §14.5/§12.9b step 4, R25/D26).
//!
//! Delegated re-sharing makes access a graph: if the owner grants A, A grants V,
//! V grants W, then revoking A must also cut V and W — unless they hold an
//! *independent* grant from a still-authorized path. Computing that subtree from
//! **server-served** edges would let a colluding server withhold a descendant's
//! edge from the revoking admin (so it is never tombstoned) while still serving
//! it to rotators/downloaders — a strong-revoke bypass parallel to tombstone
//! withholding (R16). Sourcing the walk from the **append-only audit sink**,
//! which records every grant edge and the server cannot suppress, closes it.
//!
//! This module is the pure graph computation; the ceremony feeds the returned
//! ids to [`crate::ControlChain::revoke`] as one dual-controlled batch.

use maxsecu_encoding::types::Id;
use std::collections::HashSet;

/// One read-grant edge as recorded in the external audit sink (§16.5): the file,
/// who granted, and who received. The sink is append-only and independent of the
/// app server, so a server cannot hide an edge from this source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantEdge {
    pub file_id: Id,
    pub granted_by: Id,
    pub recipient: Id,
}

/// Compute the full set of users to tombstone to truly cut off `r` from `file_id`
/// (§14.5): `r` itself **plus** every recipient reachable from `r` via
/// `granted_by` edges that has **no independent grant from a still-authorized
/// path** (one that does not pass through `r`). A descendant that the `owner`
/// can still reach without going through `r` keeps access and is *not* included.
///
/// Pure over the sink's edge log; cycle-safe (a `seen` set bounds the walk).
pub fn revocation_subtree(edges: &[GrantEdge], file_id: Id, r: Id, owner: Id) -> HashSet<Id> {
    // Nodes the owner can still reach WITHOUT passing through `r` — these keep
    // access via an independent path and must survive.
    let mut blocked = HashSet::new();
    blocked.insert(r);
    let authorized = reachable_from(owner, edges, file_id, &blocked);

    // Nodes reachable from `r` (the delegation subtree under the revoked user).
    let from_r = reachable_from(r, edges, file_id, &HashSet::new());

    // Tombstone `r` and every subtree node that has no independent authorization.
    let mut out = HashSet::new();
    out.insert(r);
    for node in from_r {
        if !authorized.contains(&node) {
            out.insert(node);
        }
    }
    out
}

/// Recipients reachable from `start` by following `granted_by -> recipient` edges
/// for `file_id`, never traversing **through** a node in `avoid` and never adding
/// an `avoid` node to the result. `start` itself is not included (only those it
/// grants to, transitively).
fn reachable_from(
    start: Id,
    edges: &[GrantEdge],
    file_id: Id,
    avoid: &HashSet<Id>,
) -> HashSet<Id> {
    let mut seen: HashSet<Id> = HashSet::new();
    let mut stack = vec![start];
    while let Some(node) = stack.pop() {
        // Do not propagate authorization through an avoided (revoked) node.
        if avoid.contains(&node) {
            continue;
        }
        for e in edges
            .iter()
            .filter(|e| e.file_id == file_id && e.granted_by == node)
        {
            if avoid.contains(&e.recipient) {
                continue;
            }
            if seen.insert(e.recipient) {
                stack.push(e.recipient);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: Id = Id([0xF1; 16]);
    const OWNER: Id = Id([0x01; 16]);
    const A: Id = Id([0x0A; 16]);
    const V: Id = Id([0x0B; 16]);
    const W: Id = Id([0x0C; 16]);
    const U: Id = Id([0x0D; 16]);

    fn edge(granted_by: Id, recipient: Id) -> GrantEdge {
        GrantEdge { file_id: FILE, granted_by, recipient }
    }

    #[test]
    fn withheld_server_edge_still_tombstoned_via_sink() {
        // Sink edge log: owner→A, A→V, V→W. Revoke A.
        let sink_edges = vec![edge(OWNER, A), edge(A, V), edge(V, W)];
        let sub = revocation_subtree(&sink_edges, FILE, A, OWNER);
        assert!(sub.contains(&A));
        assert!(sub.contains(&V));
        assert!(sub.contains(&W), "the whole subtree under A is revoked");

        // A colluding server WITHHOLDS the V→W edge from its served set. A walk
        // over the server-served edges MISSES W (the R25 bypass) — so the sink
        // source is load-bearing: it sees the edge the server hides.
        let server_edges = vec![edge(OWNER, A), edge(A, V)]; // V→W withheld
        let sub_server = revocation_subtree(&server_edges, FILE, A, OWNER);
        assert!(
            !sub_server.contains(&W),
            "the server-served walk misses W — exactly the bypass the sink closes"
        );
    }

    #[test]
    fn independent_path_survivor_is_not_revoked() {
        // owner→A, A→W, owner→U, U→W. Revoke A. W also has an independent grant
        // from U (a still-authorized path), so W keeps access.
        let edges = vec![edge(OWNER, A), edge(A, W), edge(OWNER, U), edge(U, W)];
        let sub = revocation_subtree(&edges, FILE, A, OWNER);
        assert!(sub.contains(&A));
        assert!(!sub.contains(&W), "W survives via the independent U path");
    }

    #[test]
    fn other_files_edges_are_ignored() {
        let other = Id([0xFF; 16]);
        let edges = vec![
            edge(A, V),
            GrantEdge { file_id: other, granted_by: A, recipient: W },
        ];
        let sub = revocation_subtree(&edges, FILE, A, OWNER);
        assert!(sub.contains(&V));
        assert!(!sub.contains(&W), "an edge for a different file does not extend the subtree");
    }

    #[test]
    fn cycle_in_edges_terminates() {
        // A→V, V→A (a cycle), plus owner→A. Revoke A — must terminate.
        let edges = vec![edge(OWNER, A), edge(A, V), edge(V, A)];
        let sub = revocation_subtree(&edges, FILE, A, OWNER);
        assert!(sub.contains(&A));
        assert!(sub.contains(&V));
    }
}
