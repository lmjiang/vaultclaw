use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::EntryId;

use super::health::{PasswordHealth, Strength};

/// Reason a rotation was triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationTrigger {
    /// Password exceeded maximum age.
    AgePolicy { max_age_days: i64 },
    /// Password found in a known breach.
    BreachDetected { breach_count: u64 },
    /// Password is weak (below threshold).
    WeakPassword { strength: Strength },
    /// Password is reused across entries.
    Reused,
    /// Manually requested by user.
    Manual,
}

/// State machine for a rotation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    /// Rotation identified, awaiting human approval.
    Pending,
    /// Human approved, ready to execute.
    Approved { approved_by: String, approved_at: DateTime<Utc> },
    /// Rotation in progress (password being changed).
    Rotating { started_at: DateTime<Utc> },
    /// Rotation completed successfully.
    Completed { completed_at: DateTime<Utc>, new_password_set: bool },
    /// Rotation failed.
    Failed { failed_at: DateTime<Utc>, reason: String },
    /// Rotation was dismissed/skipped by user.
    Dismissed { dismissed_at: DateTime<Utc>, reason: String },
}

/// A single rotation plan for one credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPlan {
    pub id: Uuid,
    pub entry_id: EntryId,
    pub entry_title: String,
    pub trigger: RotationTrigger,
    pub state: RotationState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Suggested new password (generated but not yet applied).
    pub suggested_password: Option<String>,
    /// Notes from the user or system.
    pub notes: String,
}

impl RotationPlan {
    pub fn new(entry_id: EntryId, entry_title: String, trigger: RotationTrigger) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            entry_id,
            entry_title,
            trigger,
            state: RotationState::Pending,
            created_at: now,
            updated_at: now,
            suggested_password: None,
            notes: String::new(),
        }
    }

    /// Approve this rotation plan.
    pub fn approve(&mut self, approved_by: impl Into<String>) -> Result<(), String> {
        if self.state != RotationState::Pending {
            return Err(format!("Cannot approve plan in state {:?}", self.state));
        }
        self.state = RotationState::Approved {
            approved_by: approved_by.into(),
            approved_at: Utc::now(),
        };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Begin executing the rotation.
    pub fn begin_rotation(&mut self) -> Result<(), String> {
        if !matches!(self.state, RotationState::Approved { .. }) {
            return Err(format!("Cannot rotate plan in state {:?}", self.state));
        }
        self.state = RotationState::Rotating { started_at: Utc::now() };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Mark rotation as completed.
    pub fn complete(&mut self, new_password_set: bool) -> Result<(), String> {
        if !matches!(self.state, RotationState::Rotating { .. }) {
            return Err(format!("Cannot complete plan in state {:?}", self.state));
        }
        self.state = RotationState::Completed {
            completed_at: Utc::now(),
            new_password_set,
        };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Mark rotation as failed.
    pub fn fail(&mut self, reason: impl Into<String>) -> Result<(), String> {
        if !matches!(self.state, RotationState::Rotating { .. }) {
            return Err(format!("Cannot fail plan in state {:?}", self.state));
        }
        self.state = RotationState::Failed {
            failed_at: Utc::now(),
            reason: reason.into(),
        };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Dismiss/skip this rotation plan.
    pub fn dismiss(&mut self, reason: impl Into<String>) -> Result<(), String> {
        if !matches!(self.state, RotationState::Pending) {
            return Err(format!("Cannot dismiss plan in state {:?}", self.state));
        }
        self.state = RotationState::Dismissed {
            dismissed_at: Utc::now(),
            reason: reason.into(),
        };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Whether this plan is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            RotationState::Completed { .. }
                | RotationState::Failed { .. }
                | RotationState::Dismissed { .. }
        )
    }

    /// Whether this plan is actionable (pending or approved).
    pub fn is_actionable(&self) -> bool {
        matches!(self.state, RotationState::Pending | RotationState::Approved { .. })
    }
}

/// Configuration for the rotation scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Maximum password age in days before suggesting rotation.
    pub max_age_days: i64,
    /// Minimum strength threshold — passwords below this trigger rotation.
    pub min_strength: Strength,
    /// Whether to auto-create rotation plans for breached passwords.
    pub rotate_on_breach: bool,
    /// Whether to auto-create rotation plans for reused passwords.
    pub rotate_on_reuse: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_age_days: 365,
            min_strength: Strength::Strong,
            rotate_on_breach: true,
            rotate_on_reuse: true,
        }
    }
}

/// Manages rotation plans and scheduling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RotationScheduler {
    plans: Vec<RotationPlan>,
    config: RotationConfig,
}

impl RotationScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: RotationConfig) -> Self {
        Self {
            plans: Vec::new(),
            config,
        }
    }

    pub fn config(&self) -> &RotationConfig {
        &self.config
    }

    /// Add a rotation plan.
    pub fn add_plan(&mut self, plan: RotationPlan) {
        self.plans.push(plan);
    }

    /// Get a plan by ID.
    pub fn get_plan(&self, plan_id: &Uuid) -> Option<&RotationPlan> {
        self.plans.iter().find(|p| p.id == *plan_id)
    }

    /// Get a mutable plan by ID.
    pub fn get_plan_mut(&mut self, plan_id: &Uuid) -> Option<&mut RotationPlan> {
        self.plans.iter_mut().find(|p| p.id == *plan_id)
    }

    /// List all plans.
    pub fn list_plans(&self) -> &[RotationPlan] {
        &self.plans
    }

    /// List pending plans (awaiting approval).
    pub fn pending_plans(&self) -> Vec<&RotationPlan> {
        self.plans.iter().filter(|p| p.state == RotationState::Pending).collect()
    }

    /// List actionable plans (pending or approved).
    pub fn actionable_plans(&self) -> Vec<&RotationPlan> {
        self.plans.iter().filter(|p| p.is_actionable()).collect()
    }

    /// Check if an entry already has an active (non-terminal) rotation plan.
    pub fn has_active_plan(&self, entry_id: &EntryId) -> bool {
        self.plans.iter().any(|p| p.entry_id == *entry_id && !p.is_terminal())
    }

    /// Scan health data and create rotation plans for entries that need rotation.
    /// Skips entries that already have an active plan.
    /// Returns the number of new plans created.
    pub fn scan_and_plan(&mut self, health_details: &[PasswordHealth]) -> usize {
        let mut created = 0;

        for detail in health_details {
            if self.has_active_plan(&detail.entry_id) {
                continue;
            }

            let trigger = self.evaluate_trigger(detail);
            if let Some(trigger) = trigger {
                let plan = RotationPlan::new(
                    detail.entry_id,
                    detail.title.clone(),
                    trigger,
                );
                self.plans.push(plan);
                created += 1;
            }
        }

        created
    }

    /// Evaluate whether a password health detail triggers rotation.
    /// Returns the highest-priority trigger if any.
    fn evaluate_trigger(&self, detail: &PasswordHealth) -> Option<RotationTrigger> {
        // Priority order: weak > reused > old
        if detail.strength < self.config.min_strength
            && detail.strength <= Strength::Fair
        {
            return Some(RotationTrigger::WeakPassword {
                strength: detail.strength,
            });
        }

        if self.config.rotate_on_reuse && detail.reused {
            return Some(RotationTrigger::Reused);
        }

        if detail.is_old && detail.age_days > self.config.max_age_days {
            return Some(RotationTrigger::AgePolicy {
                max_age_days: self.config.max_age_days,
            });
        }

        None
    }

    /// Remove all terminal (completed/failed/dismissed) plans.
    pub fn cleanup_terminal(&mut self) -> usize {
        let before = self.plans.len();
        self.plans.retain(|p| !p.is_terminal());
        before - self.plans.len()
    }

    /// Generate a summary of rotation status.
    pub fn summary(&self) -> RotationSummary {
        let mut by_state: HashMap<&'static str, usize> = HashMap::new();
        for plan in &self.plans {
            let key = match &plan.state {
                RotationState::Pending => "pending",
                RotationState::Approved { .. } => "approved",
                RotationState::Rotating { .. } => "rotating",
                RotationState::Completed { .. } => "completed",
                RotationState::Failed { .. } => "failed",
                RotationState::Dismissed { .. } => "dismissed",
            };
            *by_state.entry(key).or_insert(0) += 1;
        }

        RotationSummary {
            total_plans: self.plans.len(),
            pending: *by_state.get("pending").unwrap_or(&0),
            approved: *by_state.get("approved").unwrap_or(&0),
            rotating: *by_state.get("rotating").unwrap_or(&0),
            completed: *by_state.get("completed").unwrap_or(&0),
            failed: *by_state.get("failed").unwrap_or(&0),
            dismissed: *by_state.get("dismissed").unwrap_or(&0),
        }
    }
}

/// Summary of rotation scheduler state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSummary {
    pub total_plans: usize,
    pub pending: usize,
    pub approved: usize,
    pub rotating: usize,
    pub completed: usize,
    pub failed: usize,
    pub dismissed: usize,
}

/// Format a rotation summary as human-readable text.
pub fn format_rotation_summary(summary: &RotationSummary) -> String {
    let mut out = String::new();
    out.push_str("=== Rotation Scheduler ===\n\n");
    out.push_str(&format!("Total plans:  {}\n", summary.total_plans));
    out.push_str(&format!("Pending:      {}\n", summary.pending));
    out.push_str(&format!("Approved:     {}\n", summary.approved));
    out.push_str(&format!("In progress:  {}\n", summary.rotating));
    out.push_str(&format!("Completed:    {}\n", summary.completed));
    out.push_str(&format!("Failed:       {}\n", summary.failed));
    out.push_str(&format!("Dismissed:    {}\n", summary.dismissed));
    out
}

/// Format rotation plans as a human-readable list.
pub fn format_rotation_plans(plans: &[&RotationPlan]) -> String {
    if plans.is_empty() {
        return "No rotation plans.\n".to_string();
    }

    let mut out = String::new();
    for (i, plan) in plans.iter().enumerate() {
        let state_label = match &plan.state {
            RotationState::Pending => "PENDING".to_string(),
            RotationState::Approved { approved_by, .. } => format!("APPROVED by {}", approved_by),
            RotationState::Rotating { .. } => "ROTATING".to_string(),
            RotationState::Completed { .. } => "COMPLETED".to_string(),
            RotationState::Failed { reason, .. } => format!("FAILED: {}", reason),
            RotationState::Dismissed { reason, .. } => format!("DISMISSED: {}", reason),
        };

        let trigger_label = match &plan.trigger {
            RotationTrigger::AgePolicy { max_age_days } => format!("age > {}d", max_age_days),
            RotationTrigger::BreachDetected { breach_count } => {
                format!("breached ({}x)", breach_count)
            }
            RotationTrigger::WeakPassword { strength } => {
                format!("weak ({})", strength.label())
            }
            RotationTrigger::Reused => "reused".to_string(),
            RotationTrigger::Manual => "manual".to_string(),
        };

        out.push_str(&format!(
            "{}. [{}] {} — {} (id: {})\n",
            i + 1,
            state_label,
            plan.entry_title,
            trigger_label,
            &plan.id.to_string()[..8]
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(id: EntryId, title: &str, strength: Strength, reused: bool, age_days: i64) -> PasswordHealth {
        PasswordHealth {
            entry_id: id,
            title: title.to_string(),
            strength,
            reused,
            age_days,
            is_old: age_days > 365,
            issues: Vec::new(),
        }
    }

    // ---- RotationPlan state machine tests ----

    #[test]
    fn test_plan_creation() {
        let id = Uuid::new_v4();
        let plan = RotationPlan::new(id, "GitHub".into(), RotationTrigger::Manual);
        assert_eq!(plan.entry_id, id);
        assert_eq!(plan.state, RotationState::Pending);
        assert!(!plan.is_terminal());
        assert!(plan.is_actionable());
    }

    #[test]
    fn test_plan_approve() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        assert!(plan.approve("human").is_ok());
        assert!(matches!(plan.state, RotationState::Approved { .. }));
        assert!(plan.is_actionable());
        assert!(!plan.is_terminal());
    }

    #[test]
    fn test_plan_approve_not_pending() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        plan.approve("human").unwrap();
        assert!(plan.approve("human").is_err());
    }

    #[test]
    fn test_plan_full_lifecycle() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        plan.approve("human").unwrap();
        plan.begin_rotation().unwrap();
        assert!(matches!(plan.state, RotationState::Rotating { .. }));
        assert!(!plan.is_actionable());
        plan.complete(true).unwrap();
        assert!(matches!(plan.state, RotationState::Completed { new_password_set: true, .. }));
        assert!(plan.is_terminal());
    }

    #[test]
    fn test_plan_fail() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        plan.approve("human").unwrap();
        plan.begin_rotation().unwrap();
        plan.fail("service unavailable").unwrap();
        assert!(matches!(plan.state, RotationState::Failed { .. }));
        assert!(plan.is_terminal());
    }

    #[test]
    fn test_plan_dismiss() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        plan.dismiss("not needed").unwrap();
        assert!(matches!(plan.state, RotationState::Dismissed { .. }));
        assert!(plan.is_terminal());
    }

    #[test]
    fn test_plan_dismiss_not_pending() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        plan.approve("human").unwrap();
        assert!(plan.dismiss("too late").is_err());
    }

    #[test]
    fn test_begin_rotation_not_approved() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        assert!(plan.begin_rotation().is_err());
    }

    #[test]
    fn test_complete_not_rotating() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        assert!(plan.complete(true).is_err());
    }

    #[test]
    fn test_fail_not_rotating() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        assert!(plan.fail("oops").is_err());
    }

    // ---- RotationScheduler tests ----

    #[test]
    fn test_scheduler_new() {
        let sched = RotationScheduler::new();
        assert!(sched.list_plans().is_empty());
        assert_eq!(sched.config().max_age_days, 365);
    }

    #[test]
    fn test_scheduler_with_config() {
        let config = RotationConfig {
            max_age_days: 180,
            min_strength: Strength::VeryStrong,
            rotate_on_breach: false,
            rotate_on_reuse: false,
        };
        let sched = RotationScheduler::with_config(config);
        assert_eq!(sched.config().max_age_days, 180);
        assert!(!sched.config().rotate_on_breach);
    }

    #[test]
    fn test_scheduler_add_and_get() {
        let mut sched = RotationScheduler::new();
        let plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        let plan_id = plan.id;
        sched.add_plan(plan);

        assert_eq!(sched.list_plans().len(), 1);
        assert!(sched.get_plan(&plan_id).is_some());
        assert!(sched.get_plan(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_scheduler_get_plan_mut() {
        let mut sched = RotationScheduler::new();
        let plan = RotationPlan::new(Uuid::new_v4(), "GitHub".into(), RotationTrigger::Manual);
        let plan_id = plan.id;
        sched.add_plan(plan);

        let plan = sched.get_plan_mut(&plan_id).unwrap();
        plan.approve("human").unwrap();
        assert!(matches!(sched.get_plan(&plan_id).unwrap().state, RotationState::Approved { .. }));
    }

    #[test]
    fn test_scheduler_pending_plans() {
        let mut sched = RotationScheduler::new();
        let mut plan1 = RotationPlan::new(Uuid::new_v4(), "A".into(), RotationTrigger::Manual);
        let plan2 = RotationPlan::new(Uuid::new_v4(), "B".into(), RotationTrigger::Manual);
        plan1.approve("human").unwrap();
        sched.add_plan(plan1);
        sched.add_plan(plan2);

        assert_eq!(sched.pending_plans().len(), 1);
        assert_eq!(sched.actionable_plans().len(), 2);
    }

    #[test]
    fn test_scheduler_has_active_plan() {
        let mut sched = RotationScheduler::new();
        let entry_id = Uuid::new_v4();
        let plan = RotationPlan::new(entry_id, "GitHub".into(), RotationTrigger::Manual);
        sched.add_plan(plan);

        assert!(sched.has_active_plan(&entry_id));
        assert!(!sched.has_active_plan(&Uuid::new_v4()));
    }

    #[test]
    fn test_scheduler_has_active_plan_terminal() {
        let mut sched = RotationScheduler::new();
        let entry_id = Uuid::new_v4();
        let mut plan = RotationPlan::new(entry_id, "GitHub".into(), RotationTrigger::Manual);
        plan.dismiss("not needed").unwrap();
        sched.add_plan(plan);

        // Dismissed plan is terminal, so no active plan
        assert!(!sched.has_active_plan(&entry_id));
    }

    #[test]
    fn test_scan_and_plan_weak() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let details = vec![health(id, "Weak", Strength::VeryWeak, false, 10)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 1);
        assert!(matches!(
            sched.list_plans()[0].trigger,
            RotationTrigger::WeakPassword { .. }
        ));
    }

    #[test]
    fn test_scan_and_plan_reused() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let details = vec![health(id, "Reused", Strength::Strong, true, 10)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 1);
        assert_eq!(sched.list_plans()[0].trigger, RotationTrigger::Reused);
    }

    #[test]
    fn test_scan_and_plan_old() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let details = vec![health(id, "Old", Strength::Strong, false, 400)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 1);
        assert!(matches!(
            sched.list_plans()[0].trigger,
            RotationTrigger::AgePolicy { .. }
        ));
    }

    #[test]
    fn test_scan_and_plan_strong_not_old() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let details = vec![health(id, "Good", Strength::Strong, false, 100)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 0);
    }

    #[test]
    fn test_scan_and_plan_skips_existing_active() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let plan = RotationPlan::new(id, "Weak".into(), RotationTrigger::Manual);
        sched.add_plan(plan);

        let details = vec![health(id, "Weak", Strength::VeryWeak, false, 10)];
        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 0); // Already has active plan
    }

    #[test]
    fn test_scan_and_plan_after_terminal() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        let mut plan = RotationPlan::new(id, "Weak".into(), RotationTrigger::Manual);
        plan.dismiss("old").unwrap();
        sched.add_plan(plan);

        let details = vec![health(id, "Weak", Strength::VeryWeak, false, 10)];
        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 1); // Terminal plan doesn't block
    }

    #[test]
    fn test_scan_and_plan_reuse_disabled() {
        let config = RotationConfig {
            rotate_on_reuse: false,
            ..RotationConfig::default()
        };
        let mut sched = RotationScheduler::with_config(config);
        let id = Uuid::new_v4();
        let details = vec![health(id, "Reused", Strength::Strong, true, 10)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 0); // Reuse rotation disabled
    }

    #[test]
    fn test_scan_and_plan_priority_weak_over_reused() {
        let mut sched = RotationScheduler::new();
        let id = Uuid::new_v4();
        // Both weak AND reused — weak should take priority
        let details = vec![health(id, "Both", Strength::Weak, true, 10)];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 1);
        assert!(matches!(
            sched.list_plans()[0].trigger,
            RotationTrigger::WeakPassword { .. }
        ));
    }

    #[test]
    fn test_cleanup_terminal() {
        let mut sched = RotationScheduler::new();
        let mut plan1 = RotationPlan::new(Uuid::new_v4(), "A".into(), RotationTrigger::Manual);
        plan1.approve("h").unwrap();
        plan1.begin_rotation().unwrap();
        plan1.complete(true).unwrap();

        let plan2 = RotationPlan::new(Uuid::new_v4(), "B".into(), RotationTrigger::Manual);

        sched.add_plan(plan1);
        sched.add_plan(plan2);

        let cleaned = sched.cleanup_terminal();
        assert_eq!(cleaned, 1);
        assert_eq!(sched.list_plans().len(), 1);
    }

    #[test]
    fn test_summary() {
        let mut sched = RotationScheduler::new();
        let mut plan1 = RotationPlan::new(Uuid::new_v4(), "A".into(), RotationTrigger::Manual);
        plan1.approve("h").unwrap();
        plan1.begin_rotation().unwrap();
        plan1.complete(true).unwrap();

        let mut plan2 = RotationPlan::new(Uuid::new_v4(), "B".into(), RotationTrigger::Manual);
        plan2.dismiss("skip").unwrap();

        let plan3 = RotationPlan::new(Uuid::new_v4(), "C".into(), RotationTrigger::Manual);

        sched.add_plan(plan1);
        sched.add_plan(plan2);
        sched.add_plan(plan3);

        let summary = sched.summary();
        assert_eq!(summary.total_plans, 3);
        assert_eq!(summary.completed, 1);
        assert_eq!(summary.dismissed, 1);
        assert_eq!(summary.pending, 1);
    }

    #[test]
    fn test_summary_empty() {
        let sched = RotationScheduler::new();
        let summary = sched.summary();
        assert_eq!(summary.total_plans, 0);
        assert_eq!(summary.pending, 0);
    }

    // ---- Formatting tests ----

    #[test]
    fn test_format_rotation_summary() {
        let summary = RotationSummary {
            total_plans: 5,
            pending: 2,
            approved: 1,
            rotating: 0,
            completed: 1,
            failed: 0,
            dismissed: 1,
        };
        let text = format_rotation_summary(&summary);
        assert!(text.contains("Rotation Scheduler"));
        assert!(text.contains("Total plans:  5"));
        assert!(text.contains("Pending:      2"));
    }

    #[test]
    fn test_format_rotation_plans_empty() {
        let plans: Vec<&RotationPlan> = vec![];
        let text = format_rotation_plans(&plans);
        assert!(text.contains("No rotation plans"));
    }

    #[test]
    fn test_format_rotation_plans() {
        let plan1 = RotationPlan::new(
            Uuid::new_v4(),
            "GitHub".into(),
            RotationTrigger::WeakPassword { strength: Strength::Weak },
        );
        let mut plan2 = RotationPlan::new(
            Uuid::new_v4(),
            "AWS".into(),
            RotationTrigger::AgePolicy { max_age_days: 365 },
        );
        plan2.approve("human").unwrap();

        let plans: Vec<&RotationPlan> = vec![&plan1, &plan2];
        let text = format_rotation_plans(&plans);
        assert!(text.contains("GitHub"));
        assert!(text.contains("PENDING"));
        assert!(text.contains("weak"));
        assert!(text.contains("AWS"));
        assert!(text.contains("APPROVED"));
        assert!(text.contains("age > 365d"));
    }

    #[test]
    fn test_format_all_trigger_types() {
        let triggers = vec![
            RotationTrigger::AgePolicy { max_age_days: 90 },
            RotationTrigger::BreachDetected { breach_count: 42 },
            RotationTrigger::WeakPassword { strength: Strength::VeryWeak },
            RotationTrigger::Reused,
            RotationTrigger::Manual,
        ];
        for trigger in triggers {
            let plan = RotationPlan::new(Uuid::new_v4(), "Test".into(), trigger);
            let plans: Vec<&RotationPlan> = vec![&plan];
            let text = format_rotation_plans(&plans);
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn test_format_all_state_types() {
        let mut plans_vec = Vec::new();

        let p1 = RotationPlan::new(Uuid::new_v4(), "Pending".into(), RotationTrigger::Manual);
        plans_vec.push(p1);

        let mut p2 = RotationPlan::new(Uuid::new_v4(), "Approved".into(), RotationTrigger::Manual);
        p2.approve("user").unwrap();
        plans_vec.push(p2);

        let mut p3 = RotationPlan::new(Uuid::new_v4(), "Rotating".into(), RotationTrigger::Manual);
        p3.approve("user").unwrap();
        p3.begin_rotation().unwrap();
        plans_vec.push(p3);

        let mut p4 = RotationPlan::new(Uuid::new_v4(), "Completed".into(), RotationTrigger::Manual);
        p4.approve("user").unwrap();
        p4.begin_rotation().unwrap();
        p4.complete(true).unwrap();
        plans_vec.push(p4);

        let mut p5 = RotationPlan::new(Uuid::new_v4(), "Failed".into(), RotationTrigger::Manual);
        p5.approve("user").unwrap();
        p5.begin_rotation().unwrap();
        p5.fail("timeout").unwrap();
        plans_vec.push(p5);

        let mut p6 = RotationPlan::new(Uuid::new_v4(), "Dismissed".into(), RotationTrigger::Manual);
        p6.dismiss("not needed").unwrap();
        plans_vec.push(p6);

        let refs: Vec<&RotationPlan> = plans_vec.iter().collect();
        let text = format_rotation_plans(&refs);
        assert!(text.contains("PENDING"));
        assert!(text.contains("APPROVED"));
        assert!(text.contains("ROTATING"));
        assert!(text.contains("COMPLETED"));
        assert!(text.contains("FAILED: timeout"));
        assert!(text.contains("DISMISSED: not needed"));
    }

    // ---- Serialization tests ----

    #[test]
    fn test_rotation_trigger_serialization() {
        let triggers = vec![
            RotationTrigger::AgePolicy { max_age_days: 90 },
            RotationTrigger::BreachDetected { breach_count: 42 },
            RotationTrigger::WeakPassword { strength: Strength::Weak },
            RotationTrigger::Reused,
            RotationTrigger::Manual,
        ];
        for trigger in triggers {
            let json = serde_json::to_string(&trigger).unwrap();
            let parsed: RotationTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, trigger);
        }
    }

    #[test]
    fn test_rotation_plan_serialization() {
        let plan = RotationPlan::new(
            Uuid::new_v4(),
            "GitHub".into(),
            RotationTrigger::Manual,
        );
        let json = serde_json::to_string(&plan).unwrap();
        let parsed: RotationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entry_title, "GitHub");
        assert_eq!(parsed.state, RotationState::Pending);
    }

    #[test]
    fn test_rotation_config_serialization() {
        let config = RotationConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RotationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_age_days, 365);
        assert!(parsed.rotate_on_breach);
    }

    #[test]
    fn test_scheduler_serialization() {
        let mut sched = RotationScheduler::new();
        sched.add_plan(RotationPlan::new(Uuid::new_v4(), "Test".into(), RotationTrigger::Manual));

        let json = serde_json::to_string(&sched).unwrap();
        let parsed: RotationScheduler = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.list_plans().len(), 1);
    }

    #[test]
    fn test_rotation_summary_serialization() {
        let sched = RotationScheduler::new();
        let summary = sched.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: RotationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_plans, 0);
    }

    #[test]
    fn test_rotation_state_serialization_all_variants() {
        let states = vec![
            RotationState::Pending,
            RotationState::Approved { approved_by: "user".into(), approved_at: Utc::now() },
            RotationState::Rotating { started_at: Utc::now() },
            RotationState::Completed { completed_at: Utc::now(), new_password_set: true },
            RotationState::Failed { failed_at: Utc::now(), reason: "err".into() },
            RotationState::Dismissed { dismissed_at: Utc::now(), reason: "skip".into() },
        ];
        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: RotationState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn test_scan_multiple_entries() {
        let mut sched = RotationScheduler::new();
        let details = vec![
            health(Uuid::new_v4(), "Weak1", Strength::VeryWeak, false, 10),
            health(Uuid::new_v4(), "Good", Strength::Strong, false, 100),
            health(Uuid::new_v4(), "Reused", Strength::Strong, true, 10),
            health(Uuid::new_v4(), "Old", Strength::Strong, false, 400),
        ];

        let created = sched.scan_and_plan(&details);
        assert_eq!(created, 3); // Weak1, Reused, Old — not Good
        assert_eq!(sched.list_plans().len(), 3);
    }

    #[test]
    fn test_plan_with_suggested_password() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "Test".into(), RotationTrigger::Manual);
        plan.suggested_password = Some("new_strong_password_123!".to_string());
        assert_eq!(plan.suggested_password.as_deref(), Some("new_strong_password_123!"));
    }

    #[test]
    fn test_plan_with_notes() {
        let mut plan = RotationPlan::new(Uuid::new_v4(), "Test".into(), RotationTrigger::Manual);
        plan.notes = "User requested manual rotation".to_string();
        assert!(!plan.notes.is_empty());
    }

    #[test]
    fn test_summary_all_states() {
        let mut sched = RotationScheduler::new();

        // Pending
        sched.add_plan(RotationPlan::new(Uuid::new_v4(), "P".into(), RotationTrigger::Manual));

        // Approved
        let mut p = RotationPlan::new(Uuid::new_v4(), "A".into(), RotationTrigger::Manual);
        p.approve("h").unwrap();
        sched.add_plan(p);

        // Rotating
        let mut p = RotationPlan::new(Uuid::new_v4(), "R".into(), RotationTrigger::Manual);
        p.approve("h").unwrap();
        p.begin_rotation().unwrap();
        sched.add_plan(p);

        // Failed
        let mut p = RotationPlan::new(Uuid::new_v4(), "F".into(), RotationTrigger::Manual);
        p.approve("h").unwrap();
        p.begin_rotation().unwrap();
        p.fail("err").unwrap();
        sched.add_plan(p);

        let summary = sched.summary();
        assert_eq!(summary.pending, 1);
        assert_eq!(summary.approved, 1);
        assert_eq!(summary.rotating, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.dismissed, 0);
    }
}
