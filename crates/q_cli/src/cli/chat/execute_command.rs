use std::collections::VecDeque;
use std::io::{
    self,
    Write,
};
use std::os::fd::{
    AsFd,
    AsRawFd,
    FromRawFd,
    RawFd,
};
use std::path::Path;
use std::sync::Arc;

use console::strip_ansi_codes;
// use fig_os_shim::Context;
use fig_util::terminal::{CommandBuilder, open_pty, AsyncMasterPtyExt};
use filedescriptor::FileDescriptor;
use nix::fcntl::{
    FcntlArg,
    FdFlag,
    OFlag,
    fcntl,
    open,
};
use nix::libc;
use nix::pty::{
    Winsize,
    grantpt,
    posix_openpt,
    ptsname,
    unlockpt,
};
use nix::sys::signal::{
    SigHandler,
    Signal,
    signal,
};
use nix::sys::stat::Mode;
use portable_pty::unix::close_random_fds;
use portable_pty::PtySize;
use tokio::io::unix::AsyncFd;
use tokio::select;
use tokio::sync::mpsc::channel;
nix::ioctl_write_ptr_bad!(ioctl_tiocswinsz, libc::TIOCSWINSZ, Winsize);

use eyre::{
    Context as EyreContext,
    Result,
};
use tracing::error;

pub struct ExecuteShellCommand {}

/// Helper function to set the close-on-exec flag for a raw descriptor
fn cloexec(fd: RawFd) -> Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFD)?;
    fcntl(
        fd,
        FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC),
    )?;
    Ok(())
}

use crossterm::{
    terminal::{enable_raw_mode, disable_raw_mode, size},
    event::{self, Event, KeyEvent, KeyCode},
};

impl ExecuteShellCommand {
    pub async fn invoke2(command: &str) -> anyhow::Result<()> {
        // Enable raw mode
        enable_raw_mode()?;
    
        // Create a default terminal size using crossterm
        let pty_size = Self::get_terminal_size().ok().unwrap();
    
        // Open a new pseudoterminal
        let pty_pair = open_pty(&pty_size)?;
    
        // Create a command builder for the shell command
        let mut cmd_builder = CommandBuilder::new("sh");
        cmd_builder.args(["-c", command]);
    
        // Spawn the command in the PTY
        let child = pty_pair.slave.spawn_command(cmd_builder)?;
        
        // We need to share the child between tasks
        let child = Arc::new(tokio::sync::Mutex::new(child));
    
        // Get the master side of the PTY for reading/writing
        let master = pty_pair.master.get_async_master_pty()?;
        
        // We need to share the master between tasks
        let master = Arc::new(tokio::sync::Mutex::new(master));
        
        // Set up a channel to coordinate shutdown
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
    
        // Handle output from the command
        let master_clone = Arc::clone(&master);
        let child_clone = Arc::clone(&child);
        let output_handle = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let mut stdout = io::stdout();
            
            loop {
                let mut master_guard = master_clone.lock().await;
                
                match master_guard.read(&mut buffer).await {
                    Ok(0) => break, // End of stream
                    Ok(n) => {
                        stdout.write_all(&buffer[..n])?;
                        stdout.flush()?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Check if the process has exited
                        let mut child_guard = child_clone.lock().await;
                        if let Ok(Some(_)) = child_guard.try_wait() {
                            break;
                        }
                        drop(child_guard); // Release the lock
                        drop(master_guard); // Release the lock while sleeping
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        eprintln!("Error reading from PTY: {:?}", e);
                        break;
                    }
                }
            }
    
            // Signal that we're done reading output
            let _ = tx_clone.send(()).await;
            Ok::<(), anyhow::Error>(())
        });
    
        // Handle input from the user using crossterm
        let master_clone = Arc::clone(&master);
        let input_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Check if the process is done
                    Some(_) = rx.recv() => break,
    
                    // Use a separate task to poll for events to avoid blocking
                    event = tokio::task::spawn_blocking(|| event::read()) => {
                        match event {
                            Ok(Ok(Event::Key(key))) => {
                                // Convert the key event to bytes and send to the PTY
                                let bytes = Self::key_event_to_bytes(key);
                                if !bytes.is_empty() {
                                    let mut master_guard = master_clone.lock().await;
                                    if let Err(e) = master_guard.write_all(&bytes).await {
                                        eprintln!("Error writing to PTY: {:?}", e);
                                        break;
                                    }
                                }
                            }
                            Ok(Ok(Event::Resize(cols, rows))) => {
                                // Handle terminal resize
                                let size = PtySize {
                                    rows: rows as u16,
                                    cols: cols as u16,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                };
                                let mut master_guard = master_clone.lock().await;
                                let _ = master_guard.resize(size);
                            }
                            Ok(Err(e)) => {
                                eprintln!("Error reading event: {:?}", e);
                                break;
                            }
                            Err(e) => {
                                eprintln!("Task error: {:?}", e);
                                break;
                            }
                            _ => {} // Ignore other events
                        }
                    }
                }
            }
            
            Ok::<(), anyhow::Error>(())
        });
    
        // Wait for the output handler to complete
        let _ = output_handle.await;
        
        // Signal the input handler to stop
        let _ = tx.send(()).await;
        
        // Wait for the input handler to complete
        let _ = input_handle.await;
    
        // Wait for the child process to exit
        let mut child_guard = child.lock().await;
        let status = child_guard.wait()?;
    
        // Disable raw mode
        disable_raw_mode()?;
    
        println!("\nCommand exited with status: {}", status);
    
        Ok(())
    }
    
    // Helper function to get the current terminal size using crossterm
    fn get_terminal_size() -> Result<PtySize> {
        match size() {
            Ok((cols, rows)) => Ok(PtySize {
                rows: rows,
                cols: cols,
                pixel_width: 0,
                pixel_height: 0,
            }),
            Err(_) => {
                // Fall back to default size
                Ok(PtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                })
            }
        }
    }
    
    // Helper function to convert crossterm KeyEvent to bytes
    fn key_event_to_bytes(key: KeyEvent) -> Vec<u8> {
        match key.code {
            KeyCode::Char(c) => {
                // Handle Ctrl+key combinations
                if key.modifiers.contains(event::KeyModifiers::CONTROL) {
                    // Convert to control character (ASCII control chars are 1-26)
                    if c >= 'a' && c <= 'z' {
                        return vec![(c as u8) - b'a' + 1];
                    } else if c >= 'A' && c <= 'Z' {
                        return vec![(c as u8) - b'A' + 1];
                    }
                }
                // Regular character
                c.to_string().into_bytes()
            }
            KeyCode::Enter => vec![b'\r'],
            KeyCode::Backspace => vec![b'\x7f'],
            KeyCode::Esc => vec![b'\x1b'],
            KeyCode::Tab => vec![b'\t'],
            KeyCode::Up => vec![b'\x1b', b'[', b'A'],
            KeyCode::Down => vec![b'\x1b', b'[', b'B'],
            KeyCode::Right => vec![b'\x1b', b'[', b'C'],
            KeyCode::Left => vec![b'\x1b', b'[', b'D'],
            KeyCode::Home => vec![b'\x1b', b'[', b'H'],
            KeyCode::End => vec![b'\x1b', b'[', b'F'],
            KeyCode::Delete => vec![b'\x1b', b'[', b'3', b'~'],
            KeyCode::PageUp => vec![b'\x1b', b'[', b'5', b'~'],
            KeyCode::PageDown => vec![b'\x1b', b'[', b'6', b'~'],
            _ => vec![], // Ignore other keys
        }
    }

    pub async fn invoke(cmd_str: &str, mut updates: impl Write) -> Result<()> {
        // The pseudoterminal must be initialized with O_NONBLOCK since on macOS, the
        // it can not be safely set with fcntl() later on.
        // https://github.com/pkgw/stund/blob/master/tokio-pty-process/src/lib.rs#L127-L133
        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "linux"))] {
                let oflag = OFlag::O_RDWR | OFlag::O_NONBLOCK;
            } else if #[cfg(target_os = "freebsd")] {
                let oflag = OFlag::O_RDWR;
            }
        }
        let master_pty = std::sync::Arc::new(posix_openpt(oflag).context("Failed to openpt")?);

        // Allow pseudoterminal pair to be generated
        grantpt(&master_pty).context("Failed to grantpt")?;
        unlockpt(&master_pty).context("Failed to unlockpt")?;

        // Get the name of the pseudoterminal
        // SAFETY: This is done before any threads are spawned, thus it being
        // non thread safe is not an issue
        let pty_name = { unsafe { ptsname(&master_pty) }? };

        // This will be the reader
        let slave_pty = open(Path::new(&pty_name), OFlag::O_RDWR, Mode::empty())?;

        let winsize = Winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe { ioctl_tiocswinsz(slave_pty, &winsize) }?;

        cloexec(master_pty.as_fd().as_raw_fd())?;
        cloexec(slave_pty.as_raw_fd())?;

        let shell: String = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_string());

        let slave_fd = unsafe { FileDescriptor::from_raw_fd(slave_pty.as_raw_fd()) };

        let mut base_command = tokio::process::Command::new(&shell);
        let command = base_command
            .arg("-c")
            .arg("-l")
            .arg("-i")
            .arg(cmd_str)
            .stdin(slave_fd.as_stdio()?)
            .stdout(slave_fd.as_stdio()?)
            .stderr(slave_fd.as_stdio()?);

        let pre_exec_fn = move || {
            // Clean up a few things before we exec the program
            // Clear out any potentially problematic signal
            // dispositions that we might have inherited
            for signo in [
                Signal::SIGCHLD,
                Signal::SIGHUP,
                Signal::SIGINT,
                Signal::SIGQUIT,
                Signal::SIGTERM,
                Signal::SIGALRM,
            ] {
                unsafe { signal(signo, SigHandler::SigDfl) }?;
            }

            // Establish ourselves as a session leader.
            nix::unistd::setsid()?;

            // Clippy wants us to explicitly cast TIOCSCTTY using
            // type::from(), but the size and potentially signedness
            // are system dependent, which is why we're using `as _`.
            // Suppress this lint for this section of code.
            {
                // Set the pty as the controlling terminal.
                // Failure to do this means that delivery of
                // SIGWINCH won't happen when we resize the
                // terminal, among other undesirable effects.
                if unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 } {
                    return Err(io::Error::last_os_error());
                }
            }

            close_random_fds();

            Ok(())
        };

        unsafe { command.pre_exec(pre_exec_fn) };

        let mut child = command.spawn()?;

        let async_master = AsyncFd::new(master_pty.as_fd().as_raw_fd())?;

        const LINE_COUNT: usize = 1024;

        let (tx, mut rx) = channel(LINE_COUNT);
        let mut buffer = [0u8; LINE_COUNT];

        tokio::spawn(async move {
            loop {
                match async_master.readable().await {
                    Ok(mut guard) => {
                        let n = match guard.try_io(|inner| {
                            nix::unistd::read(inner.get_ref().as_raw_fd(), &mut buffer)
                                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                        }) {
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => {
                                print!("{} ", e);
                                error!(%e, "Read error");
                                break;
                            },
                            Err(_) => continue,
                        };

                        if n == 0 {
                            break;
                        }

                        let raw_output = &buffer[..n];
                        if tx.send(raw_output.to_vec()).await.is_err() {
                            error!("channel closed");
                            break;
                        }
                    },
                    Err(e) => {
                        error!(%e, "readable failed");
                        break;
                    },
                }
            }
        });

        let mut stdout_lines: VecDeque<String> = VecDeque::with_capacity(LINE_COUNT);

        let exit_status = loop {
            select! {
                biased;
                Some(line) = rx.recv() => {
                    updates.write_all(&line)?;
                    updates.flush()?;
                    if let Ok(text) = std::str::from_utf8(&line) {
                        for subline in text.split_inclusive('\n') {
                            if stdout_lines.len() >= LINE_COUNT {
                                stdout_lines.pop_front();
                            }
                            stdout_lines.push_back(strip_ansi_codes(subline).to_string().trim().to_string());
                        }
                    }
                }
                status = child.wait() => {
                    break status;
                }
            };
        }
        .wrap_err_with(|| format!("No exit status for '{}'", cmd_str))?;

        let stdout = stdout_lines.into_iter().collect::<String>();

        let _output = serde_json::json!({
            "exit_status": exit_status.code().unwrap_or(0).to_string(),
            "stdout": stdout,
        });

        child.kill().await?;

        Ok(())
    }
}
