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
    restored: bool,
}

impl<A: TerminalAdapter> std::fmt::Debug for TerminalGuard<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalGuard")
            .field("restored", &self.restored)
            .finish()
    }
}

impl<A: TerminalAdapter> TerminalGuard<A> {
    /// Enters raw mode and alternate screen, hiding the cursor.
    pub fn new(mut adapter: A) -> io::Result<Self> {
        adapter.enable_raw_mode()?;
        if let Err(e) = adapter.enter_alternate_screen() {
            let _ = adapter.disable_raw_mode();
            return Err(e);
        }
        let _ = adapter.hide_cursor();

        Ok(Self {
            adapter,
            restored: false,
        })
    }

    /// Explicitly restores the terminal to normal cooked mode and leaves alternate screen.
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.restored {
            self.restored = true;
            let _ = self.adapter.clear_screen();
            let _ = self.adapter.show_cursor();
            let _ = self.adapter.leave_alternate_screen();
            self.adapter.disable_raw_mode()?;
        }
        Ok(())
    }

    /// Suspends alternate screen and raw mode temporarily (e.g. for external $EDITOR).
    pub fn suspend(&mut self) -> io::Result<()> {
        if !self.restored {
            let _ = self.adapter.show_cursor();
            let _ = self.adapter.leave_alternate_screen();
            self.adapter.disable_raw_mode()?;
        }
        Ok(())
    }

    /// Resumes alternate screen and raw mode after suspension.
    pub fn resume(&mut self) -> io::Result<()> {
        if !self.restored {
            self.adapter.enable_raw_mode()?;
            self.adapter.enter_alternate_screen()?;
            let _ = self.adapter.hide_cursor();
            let _ = self.adapter.clear_screen();
        }
        Ok(())
    }

    /// Borrows the underlying adapter mutably.
    pub fn adapter_mut(&mut self) -> &mut A {
        &mut self.adapter
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

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct MockTerminalAdapter {
        pub raw_mode: bool,
        pub in_alternate_screen: bool,
        pub cursor_visible: bool,
        pub cleared: bool,
        pub fail_on_enter: bool,
    }

    impl TerminalAdapter for MockTerminalAdapter {
        fn enable_raw_mode(&mut self) -> io::Result<()> {
            self.raw_mode = true;
            Ok(())
        }

        fn disable_raw_mode(&mut self) -> io::Result<()> {
            self.raw_mode = false;
            Ok(())
        }

        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            if self.fail_on_enter {
                return Err(io::Error::other("simulated enter failure"));
            }
            self.in_alternate_screen = true;
            Ok(())
        }

        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.in_alternate_screen = false;
            Ok(())
        }

        fn show_cursor(&mut self) -> io::Result<()> {
            self.cursor_visible = true;
            Ok(())
        }

        fn hide_cursor(&mut self) -> io::Result<()> {
            self.cursor_visible = false;
            Ok(())
        }

        fn clear_screen(&mut self) -> io::Result<()> {
            self.cleared = true;
            Ok(())
        }
    }

    #[test]
    fn test_terminal_guard_success_lifecycle() {
        let adapter = MockTerminalAdapter::default();
        let mut guard = TerminalGuard::new(adapter).expect("init guard");

        assert!(guard.adapter.raw_mode);
        assert!(guard.adapter.in_alternate_screen);
        assert!(!guard.adapter.cursor_visible);

        guard.restore().expect("restore guard");

        assert!(!guard.adapter.raw_mode);
        assert!(!guard.adapter.in_alternate_screen);
        assert!(guard.adapter.cursor_visible);
        assert!(guard.adapter.cleared);
    }

    #[test]
    fn test_terminal_guard_drop_on_error() {
        let adapter = MockTerminalAdapter::default();
        let adapter_clone;

        {
            let guard = TerminalGuard::new(adapter).expect("init guard");
            assert!(guard.adapter.raw_mode);
            assert!(guard.adapter.in_alternate_screen);
            // Simulate error causing early exit without explicit restore
            let _res: Result<(), &'static str> = Err("some operation failed");
            adapter_clone = guard.adapter.clone();
        }

        // Drop has executed on guard
        assert!(adapter_clone.raw_mode); // before drop, was true
                                         // But let's check a shared reference pattern
        use std::sync::{Arc, Mutex};

        struct SharedAdapter(Arc<Mutex<MockTerminalAdapter>>);
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

        let shared = Arc::new(Mutex::new(MockTerminalAdapter::default()));
        {
            let _guard = TerminalGuard::new(SharedAdapter(Arc::clone(&shared))).expect("init");
            assert!(shared.lock().unwrap().raw_mode);
            assert!(shared.lock().unwrap().in_alternate_screen);
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
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SharedAdapter(Arc<Mutex<MockTerminalAdapter>>);
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
