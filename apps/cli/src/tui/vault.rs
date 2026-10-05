//! Vault onboarding presentation/confirmation. All file/network work stays in client services.
use super::app::{App, AppMode};
use crate::client::{
    vault_files,
    vault_link::{self, ReplacePreflight, UnlockSecret},
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Menu,
    ReplaceConfirm,
    RestoreSecret,
    ReplaceSecret,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    Inspect,
    Link,
    RestorePreflight,
    ReplacePreflight,
    StageRestore,
    StageReplace,
}
#[derive(Default)]
pub struct VaultModal {
    pub phase: Phase,
    pub pending: Option<Pending>,
    pub description: String,
    pub preflight: Option<ReplacePreflight>,
    pub secret: Zeroizing<String>,
    pub recovery: bool,
    pub confirmation: String,
}
impl std::fmt::Debug for VaultModal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultModal")
            .field("phase", &self.phase)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl VaultModal {
    pub fn clear_secret(&mut self) {
        self.secret.zeroize();
        self.secret.clear();
    }
    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.phase {
            Phase::Menu => match key.code {
                KeyCode::Char('l') => self.pending = Some(Pending::Link),
                KeyCode::Char('r') => self.pending = Some(Pending::RestorePreflight),
                KeyCode::Char('x') => self.pending = Some(Pending::ReplacePreflight),
                _ => {}
            },
            Phase::ReplaceConfirm => match key.code {
                KeyCode::Char(c) => self.confirmation.push(c),
                KeyCode::Backspace => {
                    self.confirmation.pop();
                }
                KeyCode::Enter if self.confirmation == "REPLACE LOCAL VAULT" => {
                    self.phase = Phase::ReplaceSecret;
                    self.confirmation.clear();
                }
                _ => {}
            },
            Phase::RestoreSecret | Phase::ReplaceSecret => match key.code {
                KeyCode::Tab => {
                    self.clear_secret();
                    self.recovery = !self.recovery;
                }
                KeyCode::Char(c) => self.secret.push(c),
                KeyCode::Backspace => {
                    self.secret.pop();
                }
                KeyCode::Enter => {
                    self.pending = Some(if self.phase == Phase::ReplaceSecret {
                        Pending::StageReplace
                    } else {
                        Pending::StageRestore
                    })
                }
                _ => {}
            },
        }
    }
}

pub async fn process_pending(app: &mut App) {
    let Some(pending) = app.vault_modal.pending.take() else {
        return;
    };
    let dir = crate::config::resolve_data_dir(app.data_dir.as_deref());
    let result: Result<(), crate::error::CliError> = async {
        match pending {
            Pending::Inspect => {
                let info = vault_link::inspect_vault_link(&dir).await?;
                app.vault_modal.description = format!("Authentication: {}\nVault: {}\nLocal: {}\nRemote: {}", app.account_state, info.status, info.local_fingerprint.as_deref().unwrap_or("absent"), info.remote_fingerprint.as_deref().unwrap_or("absent"));
            },
            Pending::Link => {
                let link = vault_link::link_local_vault_to_server(&dir).await?;
                app.vault_modal.description = format!("Vault linked to {} / {}", link.server_origin, link.account_id);
                app.sync_status = crate::client::sync::get_initial_sync_status(Some(&dir));
            },
            Pending::RestorePreflight | Pending::ReplacePreflight => {
                if pending == Pending::RestorePreflight && (crate::config::vault_file(&dir).exists() || crate::config::db_file(&dir).exists() || dir.join("vault-link.json").exists()) {
                    return Err(crate::error::CliError::VaultAlreadyInitialized);
                }
                let p = vault_link::replacement_preflight(&dir).await?;
                let c = &p.counts;
                app.vault_modal.description = format!("Current local vault: {}\nCurrent account/server: {}\nTarget: {} / {}\nTarget vault: {}\nDiscard pending {}, in-flight {}, failed {}, conflicts {}, unconfirmed objects {}.\nNothing local will be uploaded. The server vault is unchanged.",
                    p.current_fingerprint.as_deref().unwrap_or("absent"), p.current_link.as_ref().map(|l| format!("{} / {}", l.account_id, l.server_origin)).unwrap_or_else(|| "unlinked".into()),
                    p.target_link.account_id, p.target_link.server_origin, p.target_link.vault_fingerprint, c.pending, c.in_flight, c.failed, c.conflicts, c.unconfirmed_objects);
                app.vault_modal.preflight = Some(p);
                app.vault_modal.phase = if pending == Pending::ReplacePreflight { Phase::ReplaceConfirm } else { Phase::RestoreSecret };
                app.vault_modal.clear_secret(); app.vault_modal.confirmation.clear();
            },
            Pending::StageRestore | Pending::StageReplace => {
                app.sync_status = crate::client::sync::SyncStatus::Restoring;
                let secret = Zeroizing::new(std::mem::take(&mut *app.vault_modal.secret));
                let p = app.vault_modal.preflight.take().ok_or(crate::client::vault_link::LinkError::ConfirmationRequired)?;
                let unlock = if app.vault_modal.recovery { UnlockSecret::RecoveryKey(&secret) } else { UnlockSecret::Passphrase(secret.as_bytes()) };
                let replace = pending == Pending::StageReplace;
                let stage = vault_link::stage_remote_vault(&dir, &p, unlock, replace, replace).await?;
                // The complete new generation exists before touching the live key/UI.
                app.lock_and_clear()?;
                vault_files::install(&dir, stage)?;
                app.vault_modal = VaultModal::default();
                app.sync_status = crate::client::sync::get_initial_sync_status(Some(&dir));
                app.status_message = Some("Remote vault restored and linked. Unlock locally; server authentication preserved.".into());
                app.mode = AppMode::Locked;
            },
        }
        Ok(())
    }.await;
    if let Err(e) = result {
        app.vault_modal.clear_secret();
        app.vault_modal.preflight = None;
        app.vault_modal.confirmation.clear();
        app.vault_modal.phase = Phase::Menu;
        app.error_message = Some(e.to_string());
        app.sync_status = crate::client::sync::get_initial_sync_status(Some(&dir));
    }
}

pub fn render(f: &mut Frame<'_>, app: &App, area: Rect) {
    let popup = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );
    f.render_widget(Clear, popup);
    let m = &app.vault_modal;
    let prompt = match m.phase {
        Phase::Menu => "[l] Link Local Vault   [r] Restore Remote Vault\n[x] Replace Local Vault From Server (opens confirmation)".to_string(),
        Phase::ReplaceConfirm => format!("WARNING: LOCAL changes/cache will be discarded.\nType REPLACE LOCAL VAULT, then Enter:\n{}", m.confirmation),
        Phase::RestoreSecret | Phase::ReplaceSecret => format!("{} (LOCAL unlock): {}\nTab: switch passphrase/recovery key; Enter: validate and stage", if m.recovery { "Recovery key" } else { "Passphrase" }, "*".repeat(m.secret.chars().count())),
    };
    let text = format!(
        "{}\n{}\n\n{}\n\n{}\nEsc: cancel (secrets scrubbed)",
        app.sync_status,
        m.description,
        prompt,
        app.error_message.as_deref().unwrap_or("")
    );
    f.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Vault — authentication does not link a vault "),
        ),
        popup,
    );
}
