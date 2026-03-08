use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::cipher;
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::keys::{MasterKey, PasswordSecret};

/// Unique identifier for a shared vault member.
pub type MemberId = Uuid;

/// Role within a shared vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    /// Full control: add/remove members, change roles, delete vault.
    Owner,
    /// Can add/remove members (except owner), manage entries.
    Admin,
    /// Read/write credentials only.
    Member,
    /// Read-only access.
    ReadOnly,
}

impl MemberRole {
    pub fn can_manage_members(&self) -> bool {
        matches!(self, MemberRole::Owner | MemberRole::Admin)
    }

    pub fn can_write(&self) -> bool {
        !matches!(self, MemberRole::ReadOnly)
    }

    pub fn can_delete_vault(&self) -> bool {
        matches!(self, MemberRole::Owner)
    }
}

impl std::fmt::Display for MemberRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemberRole::Owner => write!(f, "Owner"),
            MemberRole::Admin => write!(f, "Admin"),
            MemberRole::Member => write!(f, "Member"),
            MemberRole::ReadOnly => write!(f, "Read-Only"),
        }
    }
}

/// A member of a shared vault.
/// The `encrypted_master_key` stores the vault's master key encrypted with
/// this member's personal key (derived from their password via Argon2id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedVaultMember {
    pub id: MemberId,
    pub name: String,
    pub role: MemberRole,
    /// The vault master key encrypted with this member's personal key.
    pub encrypted_master_key: Vec<u8>,
    /// Salt used to derive this member's personal key.
    pub salt: Vec<u8>,
    /// KDF params used for this member's personal key derivation.
    pub kdf_params: KdfParams,
    pub joined_at: String,
}

/// Configuration for a shared vault — stored alongside the vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedVaultConfig {
    pub vault_id: Uuid,
    pub vault_name: String,
    pub members: Vec<SharedVaultMember>,
    pub created_at: String,
    pub updated_at: String,
}

/// An invitation to join a shared vault.
/// The master key is encrypted with a temporary passphrase shared out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub vault_id: Uuid,
    pub vault_name: String,
    pub inviter: String,
    pub encrypted_master_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub expires_at: String,
}

/// Errors from shared vault operations.
#[derive(Debug, Clone)]
pub enum SharedVaultError {
    MemberExists(String),
    MemberNotFound(String),
    PermissionDenied(String),
    InvitationExpired,
    DecryptionFailed,
    InvalidInvitation(String),
    CryptoError(String),
}

impl std::fmt::Display for SharedVaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedVaultError::MemberExists(name) => {
                write!(f, "Member '{}' already exists", name)
            }
            SharedVaultError::MemberNotFound(name) => {
                write!(f, "Member '{}' not found", name)
            }
            SharedVaultError::PermissionDenied(msg) => {
                write!(f, "Permission denied: {}", msg)
            }
            SharedVaultError::InvitationExpired => write!(f, "Invitation has expired"),
            SharedVaultError::DecryptionFailed => {
                write!(f, "Decryption failed — wrong password or corrupted data")
            }
            SharedVaultError::InvalidInvitation(msg) => {
                write!(f, "Invalid invitation: {}", msg)
            }
            SharedVaultError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
        }
    }
}

impl std::error::Error for SharedVaultError {}

impl SharedVaultConfig {
    /// Create a new shared vault config. The creator becomes the owner.
    pub fn new(
        vault_name: &str,
        owner_name: &str,
        owner_password: &PasswordSecret,
        master_key: &MasterKey,
    ) -> Result<Self, SharedVaultError> {
        let owner = wrap_master_key_for_member(
            owner_name,
            MemberRole::Owner,
            owner_password,
            master_key,
        )?;

        let now = chrono::Utc::now().to_rfc3339();
        Ok(Self {
            vault_id: Uuid::new_v4(),
            vault_name: vault_name.to_string(),
            members: vec![owner],
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Find a member by name.
    pub fn find_member(&self, name: &str) -> Option<&SharedVaultMember> {
        self.members.iter().find(|m| m.name == name)
    }

    /// Find a member by ID.
    pub fn find_member_by_id(&self, id: MemberId) -> Option<&SharedVaultMember> {
        self.members.iter().find(|m| m.id == id)
    }

    /// Get the owner.
    pub fn owner(&self) -> Option<&SharedVaultMember> {
        self.members.iter().find(|m| m.role == MemberRole::Owner)
    }

    /// Add a member directly (when you have the master key).
    /// Requires the actor to have management permissions.
    pub fn add_member(
        &mut self,
        actor_name: &str,
        new_name: &str,
        role: MemberRole,
        new_member_password: &PasswordSecret,
        master_key: &MasterKey,
    ) -> Result<MemberId, SharedVaultError> {
        // Check actor permissions
        let actor = self
            .find_member(actor_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(actor_name.to_string()))?;
        if !actor.role.can_manage_members() {
            return Err(SharedVaultError::PermissionDenied(
                "only Owner or Admin can add members".to_string(),
            ));
        }
        // Cannot add another owner
        if role == MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "cannot add another Owner".to_string(),
            ));
        }
        // Check for duplicate
        if self.find_member(new_name).is_some() {
            return Err(SharedVaultError::MemberExists(new_name.to_string()));
        }

        let member =
            wrap_master_key_for_member(new_name, role, new_member_password, master_key)?;
        let id = member.id;
        self.members.push(member);
        self.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(id)
    }

    /// Remove a member. Owner cannot be removed.
    pub fn remove_member(
        &mut self,
        actor_name: &str,
        target_name: &str,
    ) -> Result<SharedVaultMember, SharedVaultError> {
        let actor = self
            .find_member(actor_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(actor_name.to_string()))?;
        if !actor.role.can_manage_members() {
            return Err(SharedVaultError::PermissionDenied(
                "only Owner or Admin can remove members".to_string(),
            ));
        }

        let target = self
            .find_member(target_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(target_name.to_string()))?;

        if target.role == MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "cannot remove the Owner".to_string(),
            ));
        }
        // Admin can't remove other admins unless they are the owner
        if target.role == MemberRole::Admin && actor.role != MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "only Owner can remove Admins".to_string(),
            ));
        }

        let idx = self
            .members
            .iter()
            .position(|m| m.name == target_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(target_name.to_string()))?;
        let removed = self.members.remove(idx);
        self.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(removed)
    }

    /// Change a member's role.
    pub fn change_role(
        &mut self,
        actor_name: &str,
        target_name: &str,
        new_role: MemberRole,
    ) -> Result<(), SharedVaultError> {
        let actor = self
            .find_member(actor_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(actor_name.to_string()))?;

        if actor.role != MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "only Owner can change roles".to_string(),
            ));
        }
        if new_role == MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "cannot assign Owner role".to_string(),
            ));
        }

        let target = self
            .members
            .iter_mut()
            .find(|m| m.name == target_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(target_name.to_string()))?;

        if target.role == MemberRole::Owner {
            return Err(SharedVaultError::PermissionDenied(
                "cannot change Owner's role".to_string(),
            ));
        }

        target.role = new_role;
        self.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Unlock the vault master key using a member's password.
    pub fn unlock_as(
        &self,
        member_name: &str,
        password: &PasswordSecret,
    ) -> Result<MasterKey, SharedVaultError> {
        let member = self
            .find_member(member_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(member_name.to_string()))?;
        unwrap_master_key(member, password)
    }

    /// Create an invitation for a new member.
    /// The invitation is encrypted with a temporary passphrase that must be
    /// shared with the invitee out-of-band (e.g., in person, via secure chat).
    pub fn create_invitation(
        &self,
        actor_name: &str,
        invite_passphrase: &PasswordSecret,
        master_key: &MasterKey,
        hours_valid: u32,
    ) -> Result<Invitation, SharedVaultError> {
        let actor = self
            .find_member(actor_name)
            .ok_or_else(|| SharedVaultError::MemberNotFound(actor_name.to_string()))?;
        if !actor.role.can_manage_members() {
            return Err(SharedVaultError::PermissionDenied(
                "only Owner or Admin can create invitations".to_string(),
            ));
        }

        let params = KdfParams::default();
        let salt = kdf::generate_salt(params.salt_length);
        let invite_key = kdf::derive_master_key(invite_passphrase, &salt, &params)
            .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

        let encrypted = cipher::encrypt(&invite_key, master_key.as_bytes())
            .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

        let expires =
            chrono::Utc::now() + chrono::Duration::hours(i64::from(hours_valid));

        Ok(Invitation {
            vault_id: self.vault_id,
            vault_name: self.vault_name.clone(),
            inviter: actor_name.to_string(),
            encrypted_master_key: encrypted,
            salt,
            kdf_params: params,
            expires_at: expires.to_rfc3339(),
        })
    }

    /// Accept an invitation and add yourself as a member.
    pub fn accept_invitation(
        &mut self,
        invitation: &Invitation,
        invite_passphrase: &PasswordSecret,
        new_name: &str,
        new_password: &PasswordSecret,
        role: MemberRole,
    ) -> Result<MemberId, SharedVaultError> {
        // Validate vault ID
        if invitation.vault_id != self.vault_id {
            return Err(SharedVaultError::InvalidInvitation(
                "vault ID mismatch".to_string(),
            ));
        }

        // Check expiry
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&invitation.expires_at) {
            if chrono::Utc::now() > expires {
                return Err(SharedVaultError::InvitationExpired);
            }
        }

        // Check for duplicate
        if self.find_member(new_name).is_some() {
            return Err(SharedVaultError::MemberExists(new_name.to_string()));
        }

        // Decrypt master key from invitation
        let master_key = unwrap_invitation_key(invitation, invite_passphrase)?;

        // Wrap master key with new member's password
        let member = wrap_master_key_for_member(new_name, role, new_password, &master_key)?;
        let id = member.id;
        self.members.push(member);
        self.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(id)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// List members as formatted strings.
    pub fn format_members(&self) -> Vec<String> {
        self.members
            .iter()
            .map(|m| format!("{} ({}) — joined {}", m.name, m.role, m.joined_at))
            .collect()
    }
}

// ---- Internal helpers ----

/// Derive a personal key from a member's password and wrap the master key.
fn wrap_master_key_for_member(
    name: &str,
    role: MemberRole,
    password: &PasswordSecret,
    master_key: &MasterKey,
) -> Result<SharedVaultMember, SharedVaultError> {
    let params = KdfParams::default();
    let salt = kdf::generate_salt(params.salt_length);

    let personal_key = kdf::derive_master_key(password, &salt, &params)
        .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

    let encrypted = cipher::encrypt(&personal_key, master_key.as_bytes())
        .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

    Ok(SharedVaultMember {
        id: Uuid::new_v4(),
        name: name.to_string(),
        role,
        encrypted_master_key: encrypted,
        salt,
        kdf_params: params,
        joined_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Unwrap the master key using a member's password.
fn unwrap_master_key(
    member: &SharedVaultMember,
    password: &PasswordSecret,
) -> Result<MasterKey, SharedVaultError> {
    let personal_key = kdf::derive_master_key(password, &member.salt, &member.kdf_params)
        .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

    let decrypted = cipher::decrypt(&personal_key, &member.encrypted_master_key)
        .map_err(|_| SharedVaultError::DecryptionFailed)?;

    if decrypted.len() != 32 {
        return Err(SharedVaultError::DecryptionFailed);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decrypted);
    Ok(MasterKey::from_bytes(key_bytes))
}

/// Decrypt the master key from an invitation.
fn unwrap_invitation_key(
    invitation: &Invitation,
    passphrase: &PasswordSecret,
) -> Result<MasterKey, SharedVaultError> {
    let invite_key =
        kdf::derive_master_key(passphrase, &invitation.salt, &invitation.kdf_params)
            .map_err(|e| SharedVaultError::CryptoError(e.to_string()))?;

    let decrypted = cipher::decrypt(&invite_key, &invitation.encrypted_master_key)
        .map_err(|_| SharedVaultError::DecryptionFailed)?;

    if decrypted.len() != 32 {
        return Err(SharedVaultError::DecryptionFailed);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decrypted);
    Ok(MasterKey::from_bytes(key_bytes))
}

/// Serialize an invitation to a portable JSON string.
pub fn serialize_invitation(invitation: &Invitation) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(invitation)
}

/// Deserialize an invitation from JSON.
pub fn deserialize_invitation(json: &str) -> Result<Invitation, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::password_secret;

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([42u8; 32])
    }

    fn test_password(s: &str) -> PasswordSecret {
        password_secret(s.to_string())
    }

    // ---- MemberRole tests ----

    #[test]
    fn test_role_permissions() {
        assert!(MemberRole::Owner.can_manage_members());
        assert!(MemberRole::Owner.can_write());
        assert!(MemberRole::Owner.can_delete_vault());

        assert!(MemberRole::Admin.can_manage_members());
        assert!(MemberRole::Admin.can_write());
        assert!(!MemberRole::Admin.can_delete_vault());

        assert!(!MemberRole::Member.can_manage_members());
        assert!(MemberRole::Member.can_write());
        assert!(!MemberRole::Member.can_delete_vault());

        assert!(!MemberRole::ReadOnly.can_manage_members());
        assert!(!MemberRole::ReadOnly.can_write());
        assert!(!MemberRole::ReadOnly.can_delete_vault());
    }

    #[test]
    fn test_role_display() {
        assert_eq!(MemberRole::Owner.to_string(), "Owner");
        assert_eq!(MemberRole::Admin.to_string(), "Admin");
        assert_eq!(MemberRole::Member.to_string(), "Member");
        assert_eq!(MemberRole::ReadOnly.to_string(), "Read-Only");
    }

    // ---- SharedVaultConfig tests ----

    #[test]
    fn test_new_shared_vault() {
        let mk = test_master_key();
        let pw = test_password("owner-password");
        let config = SharedVaultConfig::new("Family Vault", "Alice", &pw, &mk).unwrap();

        assert_eq!(config.vault_name, "Family Vault");
        assert_eq!(config.member_count(), 1);
        assert_eq!(config.owner().unwrap().name, "Alice");
        assert_eq!(config.owner().unwrap().role, MemberRole::Owner);
    }

    #[test]
    fn test_unlock_as_owner() {
        let mk = test_master_key();
        let pw = test_password("owner-password");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let unlocked = config.unlock_as("Alice", &pw).unwrap();
        assert_eq!(unlocked.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn test_unlock_wrong_password() {
        let mk = test_master_key();
        let pw = test_password("correct");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let wrong = test_password("wrong-password");
        let result = config.unlock_as("Alice", &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlock_nonexistent_member() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.unlock_as("Bob", &pw);
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    #[test]
    fn test_add_member() {
        let mk = test_master_key();
        let owner_pw = test_password("owner");
        let mut config =
            SharedVaultConfig::new("Vault", "Alice", &owner_pw, &mk).unwrap();

        let bob_pw = test_password("bob-password");
        config
            .add_member("Alice", "Bob", MemberRole::Member, &bob_pw, &mk)
            .unwrap();

        assert_eq!(config.member_count(), 2);
        assert!(config.find_member("Bob").is_some());
        assert_eq!(config.find_member("Bob").unwrap().role, MemberRole::Member);

        // Bob can unlock with his password
        let unlocked = config.unlock_as("Bob", &bob_pw).unwrap();
        assert_eq!(unlocked.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn test_add_member_duplicate() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        let result = config.add_member("Alice", "Bob", MemberRole::Member, &pw, &mk);
        assert!(matches!(result, Err(SharedVaultError::MemberExists(_))));
    }

    #[test]
    fn test_add_member_no_permission() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        // Bob (Member) cannot add members
        let result = config.add_member("Bob", "Carol", MemberRole::Member, &pw, &mk);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_cannot_add_owner() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.add_member("Alice", "Bob", MemberRole::Owner, &pw, &mk);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_remove_member() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        let removed = config.remove_member("Alice", "Bob").unwrap();
        assert_eq!(removed.name, "Bob");
        assert_eq!(config.member_count(), 1);
    }

    #[test]
    fn test_cannot_remove_owner() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();
        let result = config.remove_member("Bob", "Alice");
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_admin_cannot_remove_admin() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();
        config
            .add_member("Alice", "Carol", MemberRole::Admin, &pw, &mk)
            .unwrap();
        let result = config.remove_member("Bob", "Carol");
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_owner_can_remove_admin() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();
        config.remove_member("Alice", "Bob").unwrap();
        assert_eq!(config.member_count(), 1);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.remove_member("Alice", "Ghost");
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    #[test]
    fn test_remove_member_no_permission() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        config
            .add_member("Alice", "Carol", MemberRole::Member, &pw, &mk)
            .unwrap();
        let result = config.remove_member("Bob", "Carol");
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_remove_actor_not_found() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.remove_member("Ghost", "Alice");
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    #[test]
    fn test_change_role() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        config
            .change_role("Alice", "Bob", MemberRole::Admin)
            .unwrap();
        assert_eq!(config.find_member("Bob").unwrap().role, MemberRole::Admin);
    }

    #[test]
    fn test_change_role_only_owner() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();
        config
            .add_member("Alice", "Carol", MemberRole::Member, &pw, &mk)
            .unwrap();
        // Admin Bob cannot change Carol's role
        let result = config.change_role("Bob", "Carol", MemberRole::Admin);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_cannot_change_to_owner() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        let result = config.change_role("Alice", "Bob", MemberRole::Owner);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_cannot_change_owner_role() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.change_role("Alice", "Alice", MemberRole::Admin);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_change_role_target_not_found() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.change_role("Alice", "Ghost", MemberRole::Admin);
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    #[test]
    fn test_change_role_actor_not_found() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.change_role("Ghost", "Alice", MemberRole::Admin);
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    // ---- Invitation tests ----

    #[test]
    fn test_create_and_accept_invitation() {
        let mk = test_master_key();
        let owner_pw = test_password("owner");
        let mut config =
            SharedVaultConfig::new("Family", "Alice", &owner_pw, &mk).unwrap();

        let invite_phrase = test_password("secret-phrase");
        let invitation = config
            .create_invitation("Alice", &invite_phrase, &mk, 24)
            .unwrap();

        assert_eq!(invitation.vault_name, "Family");
        assert_eq!(invitation.inviter, "Alice");

        let bob_pw = test_password("bob-pw");
        let id = config
            .accept_invitation(&invitation, &invite_phrase, "Bob", &bob_pw, MemberRole::Member)
            .unwrap();

        assert_eq!(config.member_count(), 2);
        assert!(config.find_member_by_id(id).is_some());

        // Bob can unlock
        let unlocked = config.unlock_as("Bob", &bob_pw).unwrap();
        assert_eq!(unlocked.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn test_invitation_wrong_passphrase() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let invite_phrase = test_password("correct-phrase");
        let invitation = config
            .create_invitation("Alice", &invite_phrase, &mk, 24)
            .unwrap();

        let wrong_phrase = test_password("wrong-phrase");
        let bob_pw = test_password("bob");
        let result = config.accept_invitation(
            &invitation,
            &wrong_phrase,
            "Bob",
            &bob_pw,
            MemberRole::Member,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invitation_expired() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let invite_phrase = test_password("phrase");
        let mut invitation = config
            .create_invitation("Alice", &invite_phrase, &mk, 24)
            .unwrap();

        // Set expiry in the past
        invitation.expires_at =
            (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        let bob_pw = test_password("bob");
        let result = config.accept_invitation(
            &invitation,
            &invite_phrase,
            "Bob",
            &bob_pw,
            MemberRole::Member,
        );
        assert!(matches!(result, Err(SharedVaultError::InvitationExpired)));
    }

    #[test]
    fn test_invitation_wrong_vault() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let invite_phrase = test_password("phrase");
        let mut invitation = config
            .create_invitation("Alice", &invite_phrase, &mk, 24)
            .unwrap();

        invitation.vault_id = Uuid::new_v4(); // Different vault
        let bob_pw = test_password("bob");
        let result = config.accept_invitation(
            &invitation,
            &invite_phrase,
            "Bob",
            &bob_pw,
            MemberRole::Member,
        );
        assert!(matches!(
            result,
            Err(SharedVaultError::InvalidInvitation(_))
        ));
    }

    #[test]
    fn test_invitation_duplicate_member() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let invite_phrase = test_password("phrase");
        let invitation = config
            .create_invitation("Alice", &invite_phrase, &mk, 24)
            .unwrap();

        // Try to accept as "Alice" who already exists
        let result = config.accept_invitation(
            &invitation,
            &invite_phrase,
            "Alice",
            &pw,
            MemberRole::Member,
        );
        assert!(matches!(result, Err(SharedVaultError::MemberExists(_))));
    }

    #[test]
    fn test_member_cannot_create_invitation() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();

        let phrase = test_password("phrase");
        let result = config.create_invitation("Bob", &phrase, &mk, 24);
        assert!(matches!(
            result,
            Err(SharedVaultError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_invitation_actor_not_found() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let phrase = test_password("phrase");
        let result = config.create_invitation("Ghost", &phrase, &mk, 24);
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    // ---- Serialization tests ----

    #[test]
    fn test_config_json_roundtrip() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let json = config.to_json().unwrap();
        let parsed = SharedVaultConfig::from_json(&json).unwrap();
        assert_eq!(parsed.vault_name, "Vault");
        assert_eq!(parsed.member_count(), 1);
    }

    #[test]
    fn test_invitation_serialization() {
        let mk = test_master_key();
        let pw = test_password("owner");
        let config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let phrase = test_password("phrase");
        let invitation = config
            .create_invitation("Alice", &phrase, &mk, 24)
            .unwrap();

        let json = serialize_invitation(&invitation).unwrap();
        let parsed = deserialize_invitation(&json).unwrap();
        assert_eq!(parsed.vault_name, "Vault");
        assert_eq!(parsed.inviter, "Alice");
    }

    #[test]
    fn test_format_members() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();
        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();

        let lines = config.format_members();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Alice"));
        assert!(lines[0].contains("Owner"));
        assert!(lines[1].contains("Bob"));
        assert!(lines[1].contains("Admin"));
    }

    #[test]
    fn test_find_member_by_id() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let id = config
            .add_member("Alice", "Bob", MemberRole::Member, &pw, &mk)
            .unwrap();
        assert!(config.find_member_by_id(id).is_some());
        assert_eq!(config.find_member_by_id(id).unwrap().name, "Bob");

        // Random ID not found
        assert!(config.find_member_by_id(Uuid::new_v4()).is_none());
    }

    // ---- Error display tests ----

    #[test]
    fn test_error_display() {
        let errors = [
            SharedVaultError::MemberExists("Bob".into()),
            SharedVaultError::MemberNotFound("Carol".into()),
            SharedVaultError::PermissionDenied("no access".into()),
            SharedVaultError::InvitationExpired,
            SharedVaultError::DecryptionFailed,
            SharedVaultError::InvalidInvitation("bad data".into()),
            SharedVaultError::CryptoError("aead failed".into()),
        ];
        let expected_substrings = [
            "already exists",
            "not found",
            "Permission denied",
            "expired",
            "Decryption failed",
            "Invalid invitation",
            "Crypto error",
        ];
        for (err, expected) in errors.iter().zip(expected_substrings.iter()) {
            assert!(
                err.to_string().contains(expected),
                "{} should contain {}",
                err,
                expected
            );
        }
    }

    // ---- Full workflow test ----

    #[test]
    fn test_full_family_workflow() {
        let mk = test_master_key();
        let alice_pw = test_password("alice-strong-pw");

        // Alice creates shared vault
        let mut config =
            SharedVaultConfig::new("Family Vault", "Alice", &alice_pw, &mk).unwrap();
        assert_eq!(config.member_count(), 1);

        // Alice adds Bob directly as Admin
        let bob_pw = test_password("bob-pw");
        config
            .add_member("Alice", "Bob", MemberRole::Admin, &bob_pw, &mk)
            .unwrap();

        // Bob (Admin) creates invitation for Carol
        let invite_phrase = test_password("carol-invite");
        let invitation = config
            .create_invitation("Bob", &invite_phrase, &mk, 48)
            .unwrap();

        // Carol accepts invitation
        let carol_pw = test_password("carol-pw");
        config
            .accept_invitation(
                &invitation,
                &invite_phrase,
                "Carol",
                &carol_pw,
                MemberRole::Member,
            )
            .unwrap();
        assert_eq!(config.member_count(), 3);

        // All three can unlock
        assert_eq!(config.unlock_as("Alice", &alice_pw).unwrap().as_bytes(), mk.as_bytes());
        assert_eq!(config.unlock_as("Bob", &bob_pw).unwrap().as_bytes(), mk.as_bytes());
        assert_eq!(config.unlock_as("Carol", &carol_pw).unwrap().as_bytes(), mk.as_bytes());

        // Alice promotes Carol to ReadOnly, then back
        config
            .change_role("Alice", "Carol", MemberRole::ReadOnly)
            .unwrap();
        assert_eq!(
            config.find_member("Carol").unwrap().role,
            MemberRole::ReadOnly
        );
        config
            .change_role("Alice", "Carol", MemberRole::Member)
            .unwrap();

        // Bob (Admin) removes Carol
        config.remove_member("Bob", "Carol").unwrap();
        assert_eq!(config.member_count(), 2);

        // Serialize and deserialize
        let json = config.to_json().unwrap();
        let restored = SharedVaultConfig::from_json(&json).unwrap();
        assert_eq!(restored.member_count(), 2);
        assert_eq!(
            restored.unlock_as("Alice", &alice_pw).unwrap().as_bytes(),
            mk.as_bytes()
        );
    }

    #[test]
    fn test_add_member_actor_not_found() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        let result = config.add_member("Ghost", "Bob", MemberRole::Member, &pw, &mk);
        assert!(matches!(
            result,
            Err(SharedVaultError::MemberNotFound(_))
        ));
    }

    #[test]
    fn test_admin_adds_member() {
        let mk = test_master_key();
        let pw = test_password("pw");
        let mut config = SharedVaultConfig::new("Vault", "Alice", &pw, &mk).unwrap();

        config
            .add_member("Alice", "Bob", MemberRole::Admin, &pw, &mk)
            .unwrap();
        // Bob (Admin) can add members
        config
            .add_member("Bob", "Carol", MemberRole::Member, &pw, &mk)
            .unwrap();
        assert_eq!(config.member_count(), 3);
    }

    #[test]
    fn test_role_serialization() {
        let role = MemberRole::Admin;
        let json = serde_json::to_string(&role).unwrap();
        let parsed: MemberRole = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MemberRole::Admin);
    }
}
