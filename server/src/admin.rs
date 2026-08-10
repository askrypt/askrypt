//! Administrative rules: who may see the user list, and what an
//! administrator may do to an account.
//!
//! Same split as [`crate::profile`] — the rules live here as `pub(crate)`
//! free functions over [`AppState`], and [`crate::web::admin`] is a thin set
//! of handlers over them. Nothing here renders HTML, and there is
//! deliberately no JSON surface: administration is a website capability, so
//! the API's attack surface does not grow with it.
//!
//! Every destructive action goes through one of the guarded functions below,
//! so the three safety rules — no acting on yourself, never removing the last
//! administrator, and typing the address to delete — hold for the htmx path
//! and the plain-form path alike. Those rules protect *administrative* access
//! specifically: [`set_role`] applies them only to [`ADMIN_ROLE`], because
//! nothing about [`PAYMENT_USER_ROLE`] can lock anyone out.

use axum::http::StatusCode;
use chrono::Utc;

use crate::audit::{self, ClientInfo};
use crate::error::{ApiError, ApiResult};
use crate::profile;
use crate::state::AppState;
use crate::store::{ADMIN_ROLE, Account, AccountId, PAYMENT_USER_ROLE};

/// How many accounts one page of the user list shows.
pub(crate) const USERS_PER_PAGE: u32 = 50;

/// One row of the user list: the account plus the two facts the page needs
/// that the account record itself does not carry.
pub(crate) struct AdminUser {
    pub account: Account,
    pub is_admin: bool,
    /// Whether the account is on the paid storage tier.
    pub is_payment_user: bool,
    /// True for the administrator doing the looking, whose row offers no
    /// destructive actions.
    pub is_self: bool,
}

/// Does this account hold `role`?
pub(crate) async fn has_role(state: &AppState, account: AccountId, role: &str) -> ApiResult<bool> {
    let roles = state.roles.roles_for(account).await?;
    Ok(roles.iter().any(|held| held == role))
}

/// Does this account hold [`ADMIN_ROLE`]?
pub(crate) async fn is_admin(state: &AppState, account: AccountId) -> ApiResult<bool> {
    has_role(state, account, ADMIN_ROLE).await
}

/// Resolves a role name a form supplied to one this page actually offers.
///
/// The alternative is to let it reach [`crate::store::RoleStore::grant`],
/// which answers an unknown name with `StoreError::NotFound` and so a
/// misleading 404. An empty value means [`ADMIN_ROLE`]: the promote/demote
/// form predates this parameter.
pub(crate) fn known_role(name: &str) -> ApiResult<&'static str> {
    match name {
        "" | ADMIN_ROLE => Ok(ADMIN_ROLE),
        PAYMENT_USER_ROLE => Ok(PAYMENT_USER_ROLE),
        _ => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown_role",
            "no such role",
        )),
    }
}

/// One page of the user list, newest page first, plus the total account
/// count for the pager.
///
/// A fixed number of queries regardless of page size: each role's membership
/// is fetched once and folded into a lookup, never once per row.
pub(crate) async fn list_users(
    state: &AppState,
    caller: AccountId,
    page: u32,
) -> ApiResult<(Vec<AdminUser>, u64)> {
    let offset = page.saturating_mul(USERS_PER_PAGE);
    let accounts = state.accounts.list(USERS_PER_PAGE, offset).await?;
    let total = state.accounts.count().await?;
    let admins = ids_with(state, ADMIN_ROLE).await?;
    let payers = ids_with(state, PAYMENT_USER_ROLE).await?;
    let users = accounts
        .into_iter()
        .map(|account| AdminUser {
            is_admin: admins.contains(&account.id),
            is_payment_user: payers.contains(&account.id),
            is_self: account.id == caller,
            account,
        })
        .collect();
    Ok((users, total))
}

/// Bans or unbans an account, returning it as it now stands.
///
/// Banning also drops every session the account holds, so the lock-out takes
/// effect at once rather than whenever its tokens happen to expire —
/// [`crate::auth::resolve_session`] would refuse them anyway, but a banned
/// user should not keep a live token lying around.
pub(crate) async fn set_banned(
    state: &AppState,
    client: &ClientInfo,
    caller: &Account,
    target: AccountId,
    banned: bool,
) -> ApiResult<Account> {
    let mut account = load(state, target).await?;
    if banned {
        deny_self(caller, target, "ban")?;
        deny_last_admin(state, target, "ban").await?;
    }
    account.banned_at = banned.then(Utc::now);
    state.accounts.update(&account).await?;
    if banned {
        // Best-effort: the ban itself has landed, and a stale session would
        // still fail to resolve. Losing this is a tidiness problem, not a
        // security one, so it must not fail the request.
        if let Err(error) = state.sessions.delete_for_account(target).await {
            tracing::warn!(%error, "could not drop the sessions of a banned account");
        }
    }
    audit::emit(
        if banned {
            audit::ACCOUNT_BANNED
        } else {
            audit::ACCOUNT_UNBANNED
        },
        client,
        Some(target),
        &format!("by {}", caller.email),
    );
    Ok(account)
}

/// Grants or revokes one role, which must have come through [`known_role`].
///
/// Only [`ADMIN_ROLE`] is guarded: taking it away is what could leave the
/// system unadministered, whereas taking [`PAYMENT_USER_ROLE`] away merely
/// puts the account back on the standard storage quota. So an administrator
/// may move their own account on and off the paid tier.
pub(crate) async fn set_role(
    state: &AppState,
    client: &ClientInfo,
    caller: &Account,
    target: AccountId,
    role: &'static str,
    grant: bool,
) -> ApiResult<()> {
    // Confirms the account exists before writing a grant that references it.
    let account = load(state, target).await?;
    if grant {
        state.roles.grant(target, role).await?;
    } else {
        if role == ADMIN_ROLE {
            deny_self(caller, target, "demote")?;
            deny_last_admin(state, target, "demote").await?;
        }
        state.roles.revoke(target, role).await?;
    }
    audit::emit(
        if grant {
            audit::ROLE_GRANTED
        } else {
            audit::ROLE_REVOKED
        },
        client,
        Some(target),
        &format!("{role} for {} by {}", account.email, caller.email),
    );
    Ok(())
}

/// Deletes another account and everything it owns.
///
/// `confirm` must be the target's own email address, typed by the
/// administrator — the same protection the self-delete flow uses, and the
/// only guard against deleting the wrong row of a long table.
pub(crate) async fn delete_user(
    state: &AppState,
    client: &ClientInfo,
    caller: &Account,
    target: AccountId,
    confirm: &str,
) -> ApiResult<()> {
    let account = load(state, target).await?;
    deny_self(caller, target, "delete")?;
    deny_last_admin(state, target, "delete").await?;
    if !confirm.trim().eq_ignore_ascii_case(&account.email) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "confirmation_mismatch",
            "type the account's email address exactly to confirm",
        ));
    }
    // The cascade is profile's, not a second copy of it: an account deleted
    // by an administrator must leave exactly as little behind as one the
    // owner deleted themselves.
    profile::delete_account_data(state, client, &account).await?;
    audit::emit(
        audit::ACCOUNT_DELETED_BY_ADMIN,
        client,
        Some(target),
        &format!("{} by {}", account.email, caller.email),
    );
    Ok(())
}

/// Grants [`ADMIN_ROLE`] to the very first account in the system.
///
/// Called right after every account creation, on both the password and the
/// Google path. The rule is deliberately narrow — no administrator exists
/// *and* this is the only account — so it can never promote a later
/// registration just because the administrators were all deleted. It runs
/// after the insert has committed, so `count` already includes this account.
///
/// Never fails a registration: a server whose first account did not become an
/// administrator is recoverable with `askrypt-server grant-admin`, whereas a
/// registration that 500s is not.
pub(crate) async fn bootstrap_first_admin(state: &AppState, account: &Account) {
    match first_account_without_admins(state).await {
        Ok(false) => {}
        Ok(true) => match state.roles.grant(account.id, ADMIN_ROLE).await {
            Ok(()) => tracing::info!(
                account = %account.id,
                "first account registered; granted {ADMIN_ROLE}"
            ),
            Err(error) => tracing::warn!(
                %error,
                account = %account.id,
                "could not grant {ADMIN_ROLE} to the first account; \
                 use `askrypt-server grant-admin` to recover"
            ),
        },
        Err(error) => tracing::warn!(?error, "could not check for a first administrator"),
    }
}

async fn first_account_without_admins(state: &AppState) -> ApiResult<bool> {
    if !state.roles.accounts_with(ADMIN_ROLE).await?.is_empty() {
        return Ok(false);
    }
    Ok(state.accounts.count().await? == 1)
}

async fn ids_with(state: &AppState, role: &str) -> ApiResult<std::collections::HashSet<AccountId>> {
    Ok(state.roles.accounts_with(role).await?.into_iter().collect())
}

async fn load(state: &AppState, id: AccountId) -> ApiResult<Account> {
    state
        .accounts
        .get(id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such account"))
}

/// An administrator acting on their own row would be one click from locking
/// themselves out, so the page never offers it and this refuses it anyway.
fn deny_self(caller: &Account, target: AccountId, action: &str) -> ApiResult<()> {
    if caller.id == target {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "cannot_target_self",
            format!("you cannot {action} your own account from this page"),
        ));
    }
    Ok(())
}

/// Keeps at least one administrator in the system. Without this, banning or
/// demoting the wrong row would leave nobody able to undo it.
async fn deny_last_admin(state: &AppState, target: AccountId, action: &str) -> ApiResult<()> {
    let admins = state.roles.accounts_with(ADMIN_ROLE).await?;
    if admins.len() == 1 && admins[0] == target {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "last_admin",
            format!(
                "this is the only administrator; grant {ADMIN_ROLE} to another \
                 account before you {action} this one"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewAccount;

    async fn account(state: &AppState, email: &str) -> Account {
        state
            .accounts
            .create(NewAccount {
                email: email.to_string(),
                password_hash: Some("x".into()),
                google_sub: None,
            })
            .await
            .unwrap()
    }

    fn client() -> ClientInfo {
        ClientInfo {
            ip: "127.0.0.1".into(),
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn the_first_account_becomes_an_admin_and_the_second_does_not() {
        let state = AppState::in_memory();

        let first = account(&state, "first@example.com").await;
        bootstrap_first_admin(&state, &first).await;
        assert!(is_admin(&state, first.id).await.unwrap());

        let second = account(&state, "second@example.com").await;
        bootstrap_first_admin(&state, &second).await;
        assert!(
            !is_admin(&state, second.id).await.unwrap(),
            "a later registration must not inherit ADMIN"
        );
    }

    /// The narrow rule in action: with the administrators gone, a *new*
    /// registration must still not be promoted — recovery is the CLI's job.
    #[tokio::test]
    async fn a_later_account_is_not_promoted_when_no_admin_remains() {
        let state = AppState::in_memory();
        let first = account(&state, "first@example.com").await;
        bootstrap_first_admin(&state, &first).await;
        state.roles.revoke(first.id, ADMIN_ROLE).await.unwrap();

        let second = account(&state, "second@example.com").await;
        bootstrap_first_admin(&state, &second).await;
        assert!(!is_admin(&state, second.id).await.unwrap());
    }

    #[tokio::test]
    async fn an_admin_cannot_ban_or_delete_themselves() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;
        account(&state, "other@example.com").await;
        state.roles.grant(admin.id, ADMIN_ROLE).await.unwrap();

        let err = set_banned(&state, &client(), &admin, admin.id, true)
            .await
            .unwrap_err();
        assert_eq!(err.code, "cannot_target_self");

        let err = delete_user(&state, &client(), &admin, admin.id, &admin.email)
            .await
            .unwrap_err();
        assert_eq!(err.code, "cannot_target_self");
    }

    #[tokio::test]
    async fn the_last_admin_cannot_be_removed_until_there_is_another() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;
        let other = account(&state, "other@example.com").await;

        // `other` acts, so the self-guard is not what refuses these.
        for action in ["ban", "demote", "delete"] {
            let err = match action {
                "ban" => set_banned(&state, &client(), &other, admin.id, true)
                    .await
                    .unwrap_err(),
                "demote" => set_role(&state, &client(), &other, admin.id, ADMIN_ROLE, false)
                    .await
                    .unwrap_err(),
                _ => delete_user(&state, &client(), &other, admin.id, &admin.email)
                    .await
                    .unwrap_err(),
            };
            assert_eq!(err.code, "last_admin", "{action} was allowed");
        }

        // A second administrator lifts the guard.
        set_role(&state, &client(), &other, other.id, ADMIN_ROLE, true)
            .await
            .unwrap();
        set_role(&state, &client(), &other, admin.id, ADMIN_ROLE, false)
            .await
            .unwrap();
        assert!(!is_admin(&state, admin.id).await.unwrap());
    }

    /// The two guards are about administrative access, so the paid tier is
    /// free of them — including on the acting administrator's own row.
    #[tokio::test]
    async fn the_paid_tier_is_unguarded_and_toggles_both_ways() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;

        // Self, and the only administrator: both guards would have fired.
        set_role(&state, &client(), &admin, admin.id, PAYMENT_USER_ROLE, true)
            .await
            .unwrap();
        assert!(has_role(&state, admin.id, PAYMENT_USER_ROLE).await.unwrap());
        set_role(
            &state,
            &client(),
            &admin,
            admin.id,
            PAYMENT_USER_ROLE,
            false,
        )
        .await
        .unwrap();
        assert!(!has_role(&state, admin.id, PAYMENT_USER_ROLE).await.unwrap());
        // Taking the paid tier away leaves administrative access alone.
        assert!(is_admin(&state, admin.id).await.unwrap());
    }

    #[tokio::test]
    async fn only_the_two_named_roles_are_addressable() {
        assert_eq!(known_role("").unwrap(), ADMIN_ROLE);
        assert_eq!(known_role(ADMIN_ROLE).unwrap(), ADMIN_ROLE);
        assert_eq!(known_role(PAYMENT_USER_ROLE).unwrap(), PAYMENT_USER_ROLE);
        // Not a 404 out of the store: the form named something we don't offer.
        let err = known_role("admin").unwrap_err();
        assert_eq!(err.code, "unknown_role");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deleting_needs_the_exact_email() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;
        let victim = account(&state, "victim@example.com").await;

        let err = delete_user(&state, &client(), &admin, victim.id, "not-the-address")
            .await
            .unwrap_err();
        assert_eq!(err.code, "confirmation_mismatch");
        assert!(state.accounts.get(victim.id).await.unwrap().is_some());

        // Case and surrounding whitespace are forgiven; the address is not.
        delete_user(&state, &client(), &admin, victim.id, " Victim@Example.com ")
            .await
            .unwrap();
        assert!(state.accounts.get(victim.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn banning_stamps_the_account_and_drops_its_sessions() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;
        let victim = account(&state, "victim@example.com").await;
        crate::auth::issue_session(&state, &victim, None, 30)
            .await
            .unwrap();

        let banned = set_banned(&state, &client(), &admin, victim.id, true)
            .await
            .unwrap();
        assert!(banned.is_banned());
        assert!(
            state
                .sessions
                .list_for_account(victim.id)
                .await
                .unwrap()
                .is_empty(),
            "a ban must not leave live sessions behind"
        );

        let restored = set_banned(&state, &client(), &admin, victim.id, false)
            .await
            .unwrap();
        assert!(!restored.is_banned());
    }

    #[tokio::test]
    async fn the_user_list_flags_roles_and_the_caller() {
        let state = AppState::in_memory();
        let admin = account(&state, "admin@example.com").await;
        bootstrap_first_admin(&state, &admin).await;
        let other = account(&state, "other@example.com").await;
        state
            .roles
            .grant(other.id, PAYMENT_USER_ROLE)
            .await
            .unwrap();

        let (users, total) = list_users(&state, admin.id, 0).await.unwrap();
        assert_eq!(total, 2);
        let row = |id| users.iter().find(|u| u.account.id == id).unwrap();
        assert!(row(admin.id).is_admin && row(admin.id).is_self);
        assert!(!row(admin.id).is_payment_user);
        assert!(!row(other.id).is_admin && !row(other.id).is_self);
        assert!(row(other.id).is_payment_user);
    }
}
