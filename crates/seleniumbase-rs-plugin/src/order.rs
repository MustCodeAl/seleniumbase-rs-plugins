//! The Kahn resolver: orders plugins by phase, `requires`, `after` and `before`.

use std::collections::{BTreeSet, HashMap};

use crate::metadata::Phase;
use crate::{PluginError, Result};

/// What the resolver needs to know about one plugin.
#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub name: String,
    pub phase: Phase,
    pub requires: Vec<String>,
    pub conflicts: Vec<String>,
    pub after: Vec<String>,
    pub before: Vec<String>,
}

/// The indexes of `nodes` in run order. Among ready nodes the lowest
/// `(phase, insertion index)` goes first, so a set of legacy plugins keeps its
/// insertion order.
pub(crate) fn resolve(nodes: &[Node]) -> Result<Vec<usize>> {
    let index: HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.name.as_str(), i))
        .collect();
    // edges[a] holds every b that must run after a.
    let mut edges: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); nodes.len()];
    for (i, node) in nodes.iter().enumerate() {
        for required in &node.requires {
            let Some(&dep) = index.get(required.as_str()) else {
                return Err(PluginError::MissingDependency {
                    plugin: node.name.clone(),
                    missing: required.clone(),
                });
            };
            edges[dep].insert(i);
        }
        for other in &node.conflicts {
            if index.contains_key(other.as_str()) {
                return Err(PluginError::Conflict {
                    a: node.name.clone(),
                    b: other.clone(),
                });
            }
        }
        for name in &node.after {
            if let Some(&dep) = index.get(name.as_str()) {
                edges[dep].insert(i);
            }
        }
        for name in &node.before {
            if let Some(&later) = index.get(name.as_str()) {
                edges[i].insert(later);
            }
        }
    }
    let mut indegree = vec![0usize; nodes.len()];
    for targets in &edges {
        for &t in targets {
            indegree[t] += 1;
        }
    }
    let mut ready: BTreeSet<(Phase, usize)> = (0..nodes.len())
        .filter(|&i| indegree[i] == 0)
        .map(|i| (nodes[i].phase, i))
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(&(phase, i)) = ready.iter().next() {
        ready.remove(&(phase, i));
        order.push(i);
        for &t in &edges[i] {
            indegree[t] -= 1;
            if indegree[t] == 0 {
                ready.insert((nodes[t].phase, t));
            }
        }
    }
    if order.len() < nodes.len() {
        let stuck = (0..nodes.len())
            .filter(|i| !order.contains(i))
            .map(|i| nodes[i].name.clone())
            .collect();
        return Err(PluginError::Cycle(stuck));
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, phase: Phase) -> Node {
        Node {
            name: name.to_owned(),
            phase,
            requires: Vec::new(),
            conflicts: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
        }
    }

    fn names(nodes: &[Node]) -> Vec<String> {
        resolve(nodes)
            .unwrap()
            .into_iter()
            .map(|i| nodes[i].name.clone())
            .collect()
    }

    #[test]
    fn phase_then_insertion_order() {
        let nodes = [
            node("watch", Phase::Observe),
            node("a", Phase::Normal),
            node("env", Phase::Prepare),
            node("b", Phase::Normal),
        ];
        assert_eq!(names(&nodes), ["env", "a", "b", "watch"]);
    }

    #[test]
    fn edges_override_phase_and_missing_after_is_ignored() {
        let mut late = node("late", Phase::Prepare);
        late.after.push("a".to_owned());
        late.after.push("absent".to_owned());
        let mut b = node("b", Phase::Normal);
        b.before.push("a".to_owned());
        let nodes = [late, node("a", Phase::Normal), b];
        assert_eq!(names(&nodes), ["b", "a", "late"]);
    }

    #[test]
    fn requires_cycle_conflict_and_missing_are_errors() {
        let mut a = node("a", Phase::Normal);
        a.requires.push("b".to_owned());
        let mut b = node("b", Phase::Normal);
        b.requires.push("a".to_owned());
        assert!(matches!(resolve(&[a.clone(), b]), Err(PluginError::Cycle(_))));
        assert!(matches!(
            resolve(&[a.clone()]),
            Err(PluginError::MissingDependency { .. })
        ));
        let mut c = node("c", Phase::Normal);
        c.conflicts.push("d".to_owned());
        assert!(matches!(
            resolve(&[c, node("d", Phase::Normal)]),
            Err(PluginError::Conflict { .. })
        ));
    }
}
