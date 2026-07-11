// SPDX-License-Identifier: Apache-2.0

//! Private derived state for selective incremental cross-file stitching.

use std::collections::{HashMap, HashSet};

use crate::graph::types::{Edge, RefRole, Symbol, SymbolKind};

use super::stitch::{GlobalIndex, resolve_pending};
use super::subgraph::PendingRef;

/// Structural identity for one deferred occurrence. The ordinal is deliberately
/// retained so two identical occurrences in one file never collapse.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PendingRefId {
    owner_file: String,
    ordinal: usize,
}

impl PendingRefId {
    pub(crate) fn new(owner_file: &str, ordinal: usize) -> Self {
        Self {
            owner_file: owner_file.to_owned(),
            ordinal,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum PendingDomain {
    Ordinary,
    Qualified,
    Module,
}

/// Target lookup spaces consulted by a pending reference. `TypeRef` is
/// deliberately installed in BOTH physical target domains: resolution prefers
/// the module index and falls back to the ordinary-symbol index, so a mutation
/// in either space can change its stored result.
fn domains(pending: &PendingRef) -> &'static [PendingDomain] {
    match pending.role {
        RefRole::ModuleRef => &[PendingDomain::Module],
        RefRole::TypeRef => &[PendingDomain::Module, PendingDomain::Ordinary],
        _ if pending.qualified => &[PendingDomain::Qualified],
        _ => &[PendingDomain::Ordinary],
    }
}

/// All derived pending-reference state. It is intentionally not persisted: a
/// restored subgraph recreates it through the same install path as fact upserts.
#[derive(Default)]
pub(crate) struct PendingState {
    pending: HashMap<PendingRefId, PendingRef>,
    by_owner: HashMap<String, Vec<PendingRefId>>,
    by_domain_name: HashMap<PendingDomain, HashMap<String, HashSet<PendingRefId>>>,
    resolved: HashMap<PendingRefId, Option<Edge>>,
}

impl PendingState {
    pub(crate) fn remove_owner(&mut self, owner: &str) {
        let Some(ids) = self.by_owner.remove(owner) else {
            return;
        };
        for id in ids {
            if let Some(pending) = self.pending.remove(&id) {
                for domain in domains(&pending) {
                    if let Some(names) = self.by_domain_name.get_mut(domain)
                        && let Some(ids) = names.get_mut(&pending.name)
                    {
                        ids.remove(&id);
                        if ids.is_empty() {
                            names.remove(&pending.name);
                        }
                    }
                }
            }
            self.resolved.remove(&id);
        }
    }

    pub(crate) fn install(&mut self, owner: &str, pending: &[PendingRef]) -> Vec<PendingRefId> {
        let mut installed = Vec::with_capacity(pending.len());
        for (ordinal, reference) in pending.iter().enumerate() {
            let id = PendingRefId::new(owner, ordinal);
            for domain in domains(reference) {
                self.by_domain_name
                    .entry(*domain)
                    .or_default()
                    .entry(reference.name.clone())
                    .or_default()
                    .insert(id.clone());
            }
            self.pending.insert(id.clone(), reference.clone());
            self.resolved.insert(id.clone(), None);
            installed.push(id);
        }
        if !installed.is_empty() {
            self.by_owner.insert(owner.to_owned(), installed.clone());
        }
        installed
    }

    /// Return every installed reference whose result can be changed by `symbol`.
    /// This uses the same namespace/enclosing predicates as `resolve_pending`.
    pub(crate) fn affected_by_symbol(&self, symbol: &Symbol) -> HashSet<PendingRefId> {
        let mut affected = HashSet::new();
        let domains: &[PendingDomain] = if symbol.kind == SymbolKind::Module {
            &[PendingDomain::Module]
        } else {
            &[PendingDomain::Ordinary, PendingDomain::Qualified]
        };
        for domain in domains {
            let name = &symbol.name;
            let Some(ids) = self
                .by_domain_name
                .get(domain)
                .and_then(|names| names.get(name))
            else {
                continue;
            };
            for id in ids {
                if let Some(pending) = self.pending.get(id)
                    && GlobalIndex::pending_matches_symbol(pending, symbol)
                {
                    affected.insert(id.clone());
                }
            }
        }
        affected
    }

    pub(crate) fn resolve(
        &mut self,
        ids: impl IntoIterator<Item = PendingRefId>,
        index: &GlobalIndex,
    ) {
        let mut ids: Vec<_> = ids.into_iter().collect();
        ids.sort();
        ids.dedup();
        for id in ids {
            if let Some(pending) = self.pending.get(&id) {
                self.resolved.insert(id, resolve_pending(pending, index));
            }
        }
    }

    pub(crate) fn resolved(&self, owner: &str, ordinal: usize) -> Option<&Option<Edge>> {
        self.resolved.get(&PendingRefId::new(owner, ordinal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{Extractor, RustExtractor};
    use crate::graph::types::RefRole;
    use crate::resolve::incremental::subgraph::build_subgraph;

    #[test]
    fn stored_state_distinguishes_missing_unresolved_and_resolved_occurrences() {
        let consumer = RustExtractor
            .extract(
                "use provider::helper;\npub fn run() { helper(); helper(); }",
                "src/consumer.rs",
            )
            .expect("extract consumer");
        let provider = RustExtractor
            .extract("pub fn helper() {}", "src/provider.rs")
            .expect("extract provider");
        let consumer_sub = build_subgraph(&consumer);
        let provider_sub = build_subgraph(&provider);
        let call_ordinals: Vec<_> = consumer_sub
            .pending
            .iter()
            .enumerate()
            .filter_map(|(ordinal, pending)| (pending.role == RefRole::Call).then_some(ordinal))
            .collect();
        assert_eq!(
            call_ordinals.len(),
            2,
            "both physical calls must be pending"
        );

        let mut state = PendingState::default();
        assert!(
            state
                .resolved(&consumer_sub.owner_file, call_ordinals[0])
                .is_none()
        );
        let installed = state.install(&consumer_sub.owner_file, &consumer_sub.pending);
        let empty_index = GlobalIndex::new();
        state.resolve(installed, &empty_index);
        for ordinal in &call_ordinals {
            assert!(matches!(
                state.resolved(&consumer_sub.owner_file, *ordinal),
                Some(None)
            ));
        }

        let index = GlobalIndex::from_symbols(&[(
            provider_sub.owner_file.as_str(),
            provider_sub.symbols.as_slice(),
        )]);
        let helper = provider_sub
            .symbols
            .iter()
            .find(|symbol| symbol.name == "helper")
            .expect("helper symbol");
        state.resolve(state.affected_by_symbol(helper), &index);
        for ordinal in &call_ordinals {
            assert!(matches!(
                state.resolved(&consumer_sub.owner_file, *ordinal),
                Some(Some(edge)) if edge.to == helper.id
            ));
        }

        state.remove_owner(&consumer_sub.owner_file);
        for ordinal in call_ordinals {
            assert!(state.resolved(&consumer_sub.owner_file, ordinal).is_none());
        }
    }

    #[test]
    fn typeref_is_affected_by_both_fallback_and_preferred_target_domains() {
        let consumer = RustExtractor
            .extract("pub struct Order { value: Config }", "src/order.rs")
            .expect("extract consumer");
        let ordinary_provider = RustExtractor
            .extract("pub struct Config {}", "src/types.rs")
            .expect("extract ordinary provider");
        let module_provider = RustExtractor
            .extract("", "src/Config.rs")
            .expect("extract module provider");
        let consumer_sub = build_subgraph(&consumer);
        let ordinary_sub = build_subgraph(&ordinary_provider);
        let module_sub = build_subgraph(&module_provider);
        let type_ordinal = consumer_sub
            .pending
            .iter()
            .position(|pending| pending.role == RefRole::TypeRef && pending.name == "Config")
            .expect("Config TypeRef pending");
        let ordinary = ordinary_sub
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Config" && symbol.kind != SymbolKind::Module)
            .expect("ordinary Config symbol");
        let module = module_sub
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Config" && symbol.kind == SymbolKind::Module)
            .expect("Config module symbol");

        let mut state = PendingState::default();
        state.install(&consumer_sub.owner_file, &consumer_sub.pending);
        let ordinary_index = GlobalIndex::from_symbols(&[(
            ordinary_sub.owner_file.as_str(),
            ordinary_sub.symbols.as_slice(),
        )]);
        let ordinary_affected = state.affected_by_symbol(ordinary);
        assert!(
            !ordinary_affected.is_empty(),
            "ordinary fallback must select TypeRef"
        );
        state.resolve(ordinary_affected, &ordinary_index);
        assert!(matches!(
            state.resolved(&consumer_sub.owner_file, type_ordinal),
            Some(Some(edge)) if edge.to == ordinary.id
        ));

        let preferred_index = GlobalIndex::from_symbols(&[
            (
                ordinary_sub.owner_file.as_str(),
                ordinary_sub.symbols.as_slice(),
            ),
            (
                module_sub.owner_file.as_str(),
                module_sub.symbols.as_slice(),
            ),
        ]);
        let module_affected = state.affected_by_symbol(module);
        assert!(
            !module_affected.is_empty(),
            "module preference must select TypeRef"
        );
        state.resolve(module_affected, &preferred_index);
        assert!(matches!(
            state.resolved(&consumer_sub.owner_file, type_ordinal),
            Some(Some(edge)) if edge.to == module.id
        ));
    }
}
