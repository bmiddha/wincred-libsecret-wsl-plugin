use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::TargetName;

/// Ordered steps for an atomic-style generation update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitStep {
    WriteSecret(TargetName),
    WriteMetadata(TargetName),
    DeleteSecret(TargetName),
}

/// A recoverable item update using metadata as the visibility commit record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationCommit {
    pub item_id: Uuid,
    pub new_generation: Uuid,
    pub previous_generation: Option<Uuid>,
}

impl GenerationCommit {
    #[must_use]
    pub fn steps(self) -> Vec<CommitStep> {
        let mut steps = vec![
            CommitStep::WriteSecret(TargetName::ItemSecret {
                item_id: self.item_id,
                generation: self.new_generation,
            }),
            CommitStep::WriteMetadata(TargetName::ItemMetadata(self.item_id)),
        ];
        if let Some(previous_generation) = self.previous_generation
            && previous_generation != self.new_generation
        {
            steps.push(CommitStep::DeleteSecret(TargetName::ItemSecret {
                item_id: self.item_id,
                generation: previous_generation,
            }));
        }
        steps
    }
}

/// Broker inventory needed to reconcile interrupted generation commits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryInventory {
    pub committed_generations: BTreeMap<Uuid, Uuid>,
    pub stored_generations: BTreeSet<(Uuid, Uuid)>,
}

/// Safe startup recovery action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    DeleteAbandonedGeneration { item_id: Uuid, generation: Uuid },
    ReportMissingCommittedGeneration { item_id: Uuid, generation: Uuid },
}

/// Plans cleanup without deleting metadata that references a missing secret.
#[must_use]
pub fn plan_recovery(inventory: &RecoveryInventory) -> Vec<RecoveryAction> {
    let mut actions = Vec::new();

    for &(item_id, generation) in &inventory.stored_generations {
        if inventory.committed_generations.get(&item_id) != Some(&generation) {
            actions.push(RecoveryAction::DeleteAbandonedGeneration {
                item_id,
                generation,
            });
        }
    }

    for (&item_id, &generation) in &inventory.committed_generations {
        if !inventory
            .stored_generations
            .contains(&(item_id, generation))
        {
            actions.push(RecoveryAction::ReportMissingCommittedGeneration {
                item_id,
                generation,
            });
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_order_makes_metadata_the_visibility_point() {
        let item_id = Uuid::new_v4();
        let old_generation = Uuid::new_v4();
        let new_generation = Uuid::new_v4();

        assert_eq!(
            GenerationCommit {
                item_id,
                new_generation,
                previous_generation: Some(old_generation),
            }
            .steps(),
            vec![
                CommitStep::WriteSecret(TargetName::ItemSecret {
                    item_id,
                    generation: new_generation,
                }),
                CommitStep::WriteMetadata(TargetName::ItemMetadata(item_id)),
                CommitStep::DeleteSecret(TargetName::ItemSecret {
                    item_id,
                    generation: old_generation,
                }),
            ]
        );
    }

    #[test]
    fn recovery_deletes_only_uncommitted_generations() {
        let item_id = Uuid::new_v4();
        let committed = Uuid::new_v4();
        let abandoned = Uuid::new_v4();
        let inventory = RecoveryInventory {
            committed_generations: BTreeMap::from([(item_id, committed)]),
            stored_generations: BTreeSet::from([(item_id, committed), (item_id, abandoned)]),
        };

        assert_eq!(
            plan_recovery(&inventory),
            vec![RecoveryAction::DeleteAbandonedGeneration {
                item_id,
                generation: abandoned,
            }]
        );
    }

    #[test]
    fn recovery_reports_corrupt_committed_metadata_without_deleting_it() {
        let item_id = Uuid::new_v4();
        let missing = Uuid::new_v4();
        let inventory = RecoveryInventory {
            committed_generations: BTreeMap::from([(item_id, missing)]),
            stored_generations: BTreeSet::new(),
        };

        assert_eq!(
            plan_recovery(&inventory),
            vec![RecoveryAction::ReportMissingCommittedGeneration {
                item_id,
                generation: missing,
            }]
        );
    }

    #[test]
    fn recovery_plans_all_interrupted_commit_permutations_deterministically() {
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let third = Uuid::from_u128(3);
        let committed = Uuid::from_u128(11);
        let abandoned = Uuid::from_u128(12);
        let inventory = RecoveryInventory {
            committed_generations: BTreeMap::from([
                (first, committed),
                (second, committed),
                (third, committed),
            ]),
            stored_generations: BTreeSet::from([
                (first, committed),
                (first, abandoned),
                (second, abandoned),
            ]),
        };

        assert_eq!(
            plan_recovery(&inventory),
            vec![
                RecoveryAction::DeleteAbandonedGeneration {
                    item_id: first,
                    generation: abandoned,
                },
                RecoveryAction::DeleteAbandonedGeneration {
                    item_id: second,
                    generation: abandoned,
                },
                RecoveryAction::ReportMissingCommittedGeneration {
                    item_id: second,
                    generation: committed,
                },
                RecoveryAction::ReportMissingCommittedGeneration {
                    item_id: third,
                    generation: committed,
                },
            ]
        );
    }
}
