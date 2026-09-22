//! Terminal lifecycle management and RAII guard (ZK-101).
//!
//! Enforces raw mode and alternate screen setup and cleanup on normal exit,
//! returned errors, and panics, preventing terminal corruption and scrubbing
//! rendered output before returning to the shell.

use std::io;

/// Abstraction over low-level terminal mode and screen operations.
pub trait TerminalAdapter {
    fn enable_raw_mode(&mut self) -> io::Result<()>;
    fn disable_raw_mode(&mut self) -> io::Result<()>;
    fn enter_alternate_screen(&mut self) -> io::Result<()>;
    fn leave_alternate_screen(&mut self) -> io::Result<()>;
    fn show_cursor(&mut self) -> io::Result<()>;
    fn hide_cursor(&mut self) -> io::Result<()>;
    fn clear_screen(&mut self) -> io::Result<()>;
}

/// Real crossterm adapter operating on the active terminal stdout.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrosstermAdapter;

impl TerminalAdapter for CrosstermAdapter {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()
    }

    fn disable_raw_mode(&mut self) -> io::Result<()> {
        crossterm::terminal::disable_raw_mode()
    }

    fn enter_alternate_screen(&mut self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)
    }

    fn leave_alternate_screen(&mut self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen)
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), crossterm::cursor::Show)
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), crossterm::cursor::Hide)
    }

    fn clear_screen(&mut self) -> io::Result<()> {
        crossterm::execute!(
            io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
        )
    }
}

/// RAII guard ensuring the terminal is cleanly restored on return, error, or panic.
pub struct TerminalGuard<A: TerminalAdapter> {
    adapter: A,
    raw_mode_enabled: bool,
    alternate_screen_active: bool,
    cursor_hidden: bool,
}

impl<A: TerminalAdapter> std::fmt::Debug for TerminalGuard<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalGuard")
            .field("raw_mode_enabled", &self.raw_mode_enabled)
            .field("alternate_screen_active", &self.alternate_screen_active)
            .field("cursor_hidden", &self.cursor_hidden)
            .field("is_fully_restored", &self.is_fully_restored())
            .finish()
    }
}

impl<A: TerminalAdapter> TerminalGuard<A> {
    /// Enters raw mode and alternate screen, hiding the cursor.
    pub fn new(mut adapter: A) -> io::Result<Self> {
        adapter.enable_raw_mode()?;
        let mut guard = Self {
            adapter,
            raw_mode_enabled: true,
            alternate_screen_active: false,
            cursor_hidden: false,
        };

        if let Err(e) = guard.adapter.enter_alternate_screen() {
            let _ = guard.restore();
            return Err(e);
        }
        guard.alternate_screen_active = true;

        if let Err(e) = guard.adapter.hide_cursor() {
            let _ = guard.restore();
            return Err(e);
        }
        guard.cursor_hidden = true;

        let _ = guard.adapter.clear_screen();

        Ok(guard)
    }

    /// Returns `true` if all terminal modes and alternate screens have been restored.
    #[must_use]
    pub fn is_fully_restored(&self) -> bool {
        !self.raw_mode_enabled && !self.alternate_screen_active && !self.cursor_hidden
    }

    /// Explicitly restores the terminal to normal cooked mode and leaves alternate screen.
    ///
    /// Cleanup operations are attempted in a safe order:
    /// 1. Clear screen (scrub sensitive plaintext before leaving alternate screen).
    /// 2. Show cursor.
    /// 3. Leave alternate screen.
    /// 4. Disable raw mode.
    ///
    /// Failures are captured and returned, but all applicable cleanup steps are attempted.
    /// State flags are only cleared upon successful execution of each step, leaving sufficient
    /// state for subsequent calls or `Drop` to retry incomplete restoration.
    pub fn restore(&mut self) -> io::Result<()> {
        let mut first_err = None;

        // 1. Clear screen to scrub rendered plaintext
        if self.alternate_screen_active {
            if let Err(e) = self.adapter.clear_screen() {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        // 2. Show cursor
        if self.cursor_hidden {
            match self.adapter.show_cursor() {
                Ok(()) => {
                    self.cursor_hidden = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        // 3. Leave alternate screen
        if self.alternate_screen_active {
            match self.adapter.leave_alternate_screen() {
                Ok(()) => {
                    self.alternate_screen_active = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        // 4. Disable raw mode
        if self.raw_mode_enabled {
            match self.adapter.disable_raw_mode() {
                Ok(()) => {
                    self.raw_mode_enabled = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Suspends alternate screen and raw mode temporarily (e.g. for external $EDITOR).
    pub fn suspend(&mut self) -> io::Result<()> {
        let mut first_err = None;

        if self.cursor_hidden {
            match self.adapter.show_cursor() {
                Ok(()) => {
                    self.cursor_hidden = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if self.alternate_screen_active {
            match self.adapter.leave_alternate_screen() {
                Ok(()) => {
                    self.alternate_screen_active = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if self.raw_mode_enabled {
            match self.adapter.disable_raw_mode() {
                Ok(()) => {
                    self.raw_mode_enabled = false;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Resumes alternate screen and raw mode after suspension.
    pub fn resume(&mut self) -> io::Result<()> {
        if !self.raw_mode_enabled {
            self.adapter.enable_raw_mode()?;
            self.raw_mode_enabled = true;
        }

        if !self.alternate_screen_active {
            self.adapter.enter_alternate_screen()?;
            self.alternate_screen_active = true;
        }

        if !self.cursor_hidden {
            self.adapter.hide_cursor()?;
            self.cursor_hidden = true;
        }

        let _ = self.adapter.clear_screen();
        Ok(())
    }

    /// Borrows the underlying adapter mutably.
    pub fn adapter_mut(&mut self) -> &mut A {
        &mut self.adapter
    }

    /// Borrows the underlying adapter immutably.
    pub fn adapter(&self) -> &A {
        &self.adapter
    }
}

impl<A: TerminalAdapter> Drop for TerminalGuard<A> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
pub mod tests {
    use super::*;
    use std::panic::catch_unwind;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct MockTerminalAdapter {
        pub raw_mode: bool,
        pub in_alternate_screen: bool,
        pub cursor_visible: bool,
        pub cleared: bool,
        pub fail_on_enter: bool,
        pub fail_on_clear: bool,
        pub fail_on_show_cursor: bool,
        pub fail_on_leave_alternate: bool,
        pub fail_on_disable_raw: bool,
        pub clear_count: usize,
        pub show_cursor_count: usize,
        pub leave_alternate_count: usize,
        pub disable_raw_count: usize,
    }

    impl TerminalAdapter for MockTerminalAdapter {
        fn enable_raw_mode(&mut self) -> io::Result<()> {
            self.raw_mode = true;
            Ok(())
        }

        fn disable_raw_mode(&mut self) -> io::Result<()> {
            self.disable_raw_count += 1;
            if self.fail_on_disable_raw {
                return Err(io::Error::other("injected disable_raw failure"));
            }
            self.raw_mode = false;
            Ok(())
        }

        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            if self.fail_on_enter {
                return Err(io::Error::other("injected enter failure"));
            }
            self.in_alternate_screen = true;
            Ok(())
        }

        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.leave_alternate_count += 1;
            if self.fail_on_leave_alternate {
                return Err(io::Error::other("injected leave_alternate failure"));
            }
            self.in_alternate_screen = false;
            Ok(())
        }

        fn show_cursor(&mut self) -> io::Result<()> {
            self.show_cursor_count += 1;
            if self.fail_on_show_cursor {
                return Err(io::Error::other("injected show_cursor failure"));
            }
            self.cursor_visible = true;
            Ok(())
        }

        fn hide_cursor(&mut self) -> io::Result<()> {
            self.cursor_visible = false;
            Ok(())
        }

        fn clear_screen(&mut self) -> io::Result<()> {
            self.clear_count += 1;
            if self.fail_on_clear {
                return Err(io::Error::other("injected clear_screen failure"));
            }
            self.cleared = true;
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    pub struct SharedAdapter(pub Arc<Mutex<MockTerminalAdapter>>);

    impl TerminalAdapter for SharedAdapter {
        fn enable_raw_mode(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().enable_raw_mode()
        }
        fn disable_raw_mode(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().disable_raw_mode()
        }
        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().enter_alternate_screen()
        }
        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().leave_alternate_screen()
        }
        fn show_cursor(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().show_cursor()
        }
        fn hide_cursor(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().hide_cursor()
        }
        fn clear_screen(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().clear_screen()
        }
    }

    #[test]
    fn test_terminal_guard_success_lifecycle() {
        let adapter = MockTerminalAdapter::default();
        let mut guard = TerminalGuard::new(adapter).expect("init guard");

        assert!(guard.adapter.raw_mode);
        assert!(guard.adapter.in_alternate_screen);
        assert!(!guard.adapter.cursor_visible);
        assert!(!guard.is_fully_restored());

        guard.restore().expect("restore guard");

        assert!(!guard.adapter.raw_mode);
        assert!(!guard.adapter.in_alternate_screen);
        assert!(guard.adapter.cursor_visible);
        assert!(guard.adapter.cleared);
        assert!(guard.is_fully_restored());
    }

    #[test]
    fn test_terminal_guard_failure_injection_and_retry_safety() {
        // 1. Injected failure at clear_screen: other steps must still execute
        let shared = Arc::new(Mutex::new(MockTerminalAdapter {
            fail_on_clear: true,
            ..Default::default()
        }));

        let mut guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
        let res = guard.restore();
        assert!(res.is_err(), "restore must return error if clear fails");
        {
            let state = shared.lock().unwrap();
            assert!(state.cursor_visible, "cursor must still be shown");
            assert!(
                !state.in_alternate_screen,
                "alternate screen must still be left"
            );
            assert!(!state.raw_mode, "raw mode must still be disabled");
        }

        // 2. Injected failure at show_cursor: leave alternate and disable raw still execute
        let shared = Arc::new(Mutex::new(MockTerminalAdapter {
            fail_on_show_cursor: true,
            ..Default::default()
        }));

        let mut guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
        let res = guard.restore();
        assert!(res.is_err());
        assert!(
            !guard.is_fully_restored(),
            "not fully restored while cursor is hidden"
        );
        {
            let state = shared.lock().unwrap();
            assert!(!state.cursor_visible);
            assert!(!state.in_alternate_screen);
            assert!(!state.raw_mode);
        }
        // Retrying after clearing failure flag restores cursor and completes
        shared.lock().unwrap().fail_on_show_cursor = false;
        guard.restore().expect("retry restore");
        assert!(guard.is_fully_restored());
        assert!(shared.lock().unwrap().cursor_visible);

        // 3. Injected failure at leave_alternate: disable_raw still executes
        let shared = Arc::new(Mutex::new(MockTerminalAdapter {
            fail_on_leave_alternate: true,
            ..Default::default()
        }));

        let mut guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
        let res = guard.restore();
        assert!(res.is_err());
        assert!(!guard.is_fully_restored());
        {
            let state = shared.lock().unwrap();
            assert!(state.cursor_visible);
            assert!(state.in_alternate_screen);
            assert!(!state.raw_mode, "raw mode must still be disabled");
        }
        // Clear failure and retry
        shared.lock().unwrap().fail_on_leave_alternate = false;
        guard.restore().expect("retry restore");
        assert!(guard.is_fully_restored());
        assert!(!shared.lock().unwrap().in_alternate_screen);

        // 4. Injected failure at disable_raw: drop retries incomplete steps
        let shared = Arc::new(Mutex::new(MockTerminalAdapter {
            fail_on_disable_raw: true,
            ..Default::default()
        }));

        {
            let mut guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
            let res = guard.restore();
            assert!(res.is_err());
            assert!(!guard.is_fully_restored());
            assert!(shared.lock().unwrap().raw_mode);
            // Clear failure before guard drops so Drop retry succeeds
            shared.lock().unwrap().fail_on_disable_raw = false;
        }
        // Drop ran on guard:
        assert!(
            !shared.lock().unwrap().raw_mode,
            "Drop must retry and disable raw mode"
        );
    }

    #[test]
    fn test_terminal_guard_drop_on_error() {
        let shared = Arc::new(Mutex::new(MockTerminalAdapter::default()));
        {
            let _guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
            assert!(shared.lock().unwrap().raw_mode);
            assert!(shared.lock().unwrap().in_alternate_screen);
            // Simulate error causing early exit without explicit restore
            let _res: Result<(), &'static str> = Err("some operation failed");
        }

        // After leaving scope, Drop must have cleaned up
        let state = shared.lock().unwrap();
        assert!(!state.raw_mode);
        assert!(!state.in_alternate_screen);
        assert!(state.cursor_visible);
        assert!(state.cleared);
    }

    #[test]
    fn test_terminal_guard_drop_on_panic() {
        let shared = Arc::new(Mutex::new(MockTerminalAdapter::default()));
        let shared_for_panic = Arc::clone(&shared);

        let result = catch_unwind(move || {
            let _guard = TerminalGuard::new(SharedAdapter(shared_for_panic)).expect("init guard");
            panic!("deliberate panic inside TUI loop");
        });

        assert!(result.is_err());
        let state = shared.lock().unwrap();
        assert!(!state.raw_mode, "raw mode must be disabled on panic");
        assert!(
            !state.in_alternate_screen,
            "alternate screen must be left on panic"
        );
        assert!(state.cursor_visible, "cursor must be shown on panic");
        assert!(state.cleared, "screen must be cleared on panic");
    }

    #[test]
    fn test_terminal_guard_suspend_and_resume() {
        let adapter = MockTerminalAdapter::default();
        let mut guard = TerminalGuard::new(adapter).expect("init guard");

        assert!(guard.adapter.raw_mode);
        assert!(guard.adapter.in_alternate_screen);

        guard.suspend().expect("suspend");
        assert!(!guard.adapter.raw_mode);
        assert!(!guard.adapter.in_alternate_screen);
        assert!(guard.adapter.cursor_visible);

        guard.resume().expect("resume");
        assert!(guard.adapter.raw_mode);
        assert!(guard.adapter.in_alternate_screen);
        assert!(!guard.adapter.cursor_visible);
    }
}
