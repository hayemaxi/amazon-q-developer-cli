use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::Path;
use std::process::{
    ExitStatus,
    Stdio,
};
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;

use console::strip_ansi_codes;
use crossterm::event::{KeyCode,KeyEvent};
use crossterm::{execute, queue};
use crossterm::style::{
    self,
    Color,
};
use eyre::{
    Context as EyreContext,
    Result,
};
use fig_util::terminal::{open_pty, CommandBuilder, SlavePty, AsyncMasterPtyExt};
use portable_pty::PtySize;
use std::os::fd::{
    AsFd,
    AsRawFd,
    FromRawFd,
    RawFd,
};
use fig_os_shim::Context;
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
use tokio::io::unix::AsyncFd;
nix::ioctl_write_ptr_bad!(ioctl_tiocswinsz, libc::TIOCSWINSZ, Winsize);
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tracing::error;

use super::{
    InvokeOutput,
    MAX_TOOL_RESPONSE_SIZE,
    OutputKind,
};
use crate::cli::chat::truncate_safe;

const READONLY_COMMANDS: &[&str] = &["ls", "cat", "echo", "pwd", "which", "head", "tail", "find", "grep"];

#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteBash {
    pub command: String,
}

impl ExecuteBash {
    pub fn requires_acceptance(&self) -> bool {
        let Some(args) = shlex::split(&self.command) else {
            return true;
        };

        const DANGEROUS_PATTERNS: &[&str] = &["<(", "$(", "`", ">", "&&", "||"];
        if args
            .iter()
            .any(|arg| DANGEROUS_PATTERNS.iter().any(|p| arg.contains(p)))
        {
            return true;
        }

        // Split commands by pipe and check each one
        let mut current_cmd = Vec::new();
        let mut all_commands = Vec::new();

        for arg in args {
            if arg == "|" {
                if !current_cmd.is_empty() {
                    all_commands.push(current_cmd);
                }
                current_cmd = Vec::new();
            } else if arg.contains("|") {
                // if pipe appears without spacing e.g. `echo myimportantfile|args rm` it won't get
                // parsed out, in this case - we want to verify before running
                return true;
            } else {
                current_cmd.push(arg);
            }
        }
        if !current_cmd.is_empty() {
            all_commands.push(current_cmd);
        }

        // Check if each command in the pipe chain starts with a safe command
        for cmd_args in all_commands {
            match cmd_args.first() {
                // Special casing for `find` so that we support most cases while safeguarding
                // against unwanted mutations
                Some(cmd)
                    if cmd == "find"
                        && cmd_args
                            .iter()
                            .any(|arg| arg.contains("-exec") || arg.contains("-delete")) =>
                {
                    return true;
                },
                Some(cmd) if !READONLY_COMMANDS.contains(&cmd.as_str()) => return true,
                None => return true,
                _ => (),
            }
        }

        false
    }

    pub async fn invoke(&self, updates: impl Write) -> Result<InvokeOutput> {
        let output = run_command(&self.command, MAX_TOOL_RESPONSE_SIZE / 3, Some(updates)).await?;
        let result = serde_json::json!({
            "exit_status": output.exit_status.unwrap_or(0).to_string(),
            "stdout": output.stdout,
            "stderr": output.stderr,
        });

        Ok(InvokeOutput {
            output: OutputKind::Json(result),
        })
    }

    /// Helper function to set the close-on-exec flag for a raw descriptor
    fn cloexec(fd: RawFd) -> Result<()> {
        let flags = fcntl(fd, FcntlArg::F_GETFD)?;
        fcntl(
            fd,
            FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC),
        )?;
        Ok(())
    }

    // Helper function to get the current terminal size using crossterm
    fn get_terminal_size() -> Result<PtySize> {
        match crossterm::terminal::size() {
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

    fn key_event_to_bytes(key: KeyEvent) -> Vec<u8> {
        match key.code {
            KeyCode::Char(c) => {
                // Handle Ctrl+key combinations
                if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
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

    pub async fn invoke2(&self, mut updates: impl Write) -> anyhow::Result<InvokeOutput> {
        // Create a default terminal size using crossterm
        let pty_size = Self::get_terminal_size().ok().unwrap();
    
        // Open a new pseudoterminal
        let pty_pair = open_pty(&pty_size)?;

        let shell: String = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_string());

        // Create a command builder for the shell command
        let mut cmd_builder = CommandBuilder::new(shell);
        cmd_builder.args(["-cli", &self.command]);
        cmd_builder.cwd(std::env::current_dir()?);

        let mut child = pty_pair.slave.spawn_command(cmd_builder)?;
        let mut master = pty_pair.master.get_async_master_pty()?;
        let master = Arc::new(tokio::sync::Mutex::new(master));

        const LINE_COUNT: usize = 1024;

        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel(LINE_COUNT);
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let mut stdout_buffer = [0u8; LINE_COUNT];
        let mut stdin_buffer = [0u8; LINE_COUNT];

        let print = |s: &str| {
            let _ = execute!(
                std::io::stdout().lock(),
                style::Print(format!("{}\n", s)),
            );
        };

        print("starting output reader");
        let master_clone = Arc::clone(&master);
        tokio::spawn(async move {
            loop {
                print("waiting for output");
                let mut master_guard = master_clone.lock().await;
                match master_guard.read(&mut stdout_buffer).await {
                    Ok(n) => {
                        print("acquired output");
                        if n == 0 {
                            print("output is empty actually");
                            break;
                        }

                        let raw_output = &stdout_buffer[..n];
                        if stdout_tx.send(raw_output.to_vec()).await.is_err() {
                            print("channel closed");
                            break;
                        }
                    },
                    Err(e) => {
                        print("read failed");
                        error!(%e, "read failed");
                        break;
                    },
                }
            }
            drop(stdout_tx);
        });

        let mut child_future = Box::pin(tokio::task::spawn_blocking(move || { child.wait(); child}));

        // Enable raw mode
        crossterm::terminal::enable_raw_mode()?;

        print("starting input writer");
        let master_clone = Arc::clone(&master);
        tokio::spawn(async move {
            loop {
                // print("waiting for input");
                if stdin_rx.is_closed() {
                    break;
                }
                if let Ok(false) = crossterm::event::poll(Duration::from_millis(20)) {
                    continue;
                }
                print("there are input events to read.");
                match crossterm::event::read() {
                    Ok(crossterm::event::Event::Key(key)) => {
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
                    Ok(crossterm::event::Event::Resize(cols, rows)) => {
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
                    Err(e) => {
                        eprintln!("Error reading event: {:?}", e);
                        break;
                    }
                    _ => {} // Ignore other events
                }
            }
        });

        let mut stdout_lines: VecDeque<String> = VecDeque::with_capacity(LINE_COUNT);
        let child = loop {
            print("waiting on items");
            tokio::select! {
                biased;
                line = stdout_rx.recv() => {
                    if line.is_none() {
                        print("line is none");
                        break Ok(None)
                    }
                    let line = line.unwrap();
                    print("record output");
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
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    print("timeout reached");
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Command execution timed out"
                    ));
                }
                result = &mut child_future => {
                    match result {
                        Ok(mut child) => {
                            print("child awaited");
                            break Ok(Some(child));
                        },
                        Err(e) => {
                            print("child error");
                            break Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("child error: {}", e)
                            ));
                        }
                    }
                }
            };
        }
        .wrap_err_with(|| format!("No exit status for '{}'", &self.command)).map_err(|e| anyhow::anyhow!(e))?;
        drop(stdin_tx);
        let mut child = if child.is_some() {
            child.unwrap()
        } else {
            // Cannot execute if we exited the loop with the child object
            child_future.await?
        };

        let exit_status = child.wait()?;

        // now I need to wait for the child to complete (without blocking permamently hopefully), in case we exited from a closed stdout channel
        let stdout = stdout_lines.into_iter().collect::<String>();

        let output = serde_json::json!({
            "exit_status": exit_status.exit_code().to_string(),
            "stdout": format!(
                "{}{}",
                truncate_safe(&stdout, MAX_TOOL_RESPONSE_SIZE / 3),
                if stdout.len() > MAX_TOOL_RESPONSE_SIZE / 3 {
                    " ... truncated"
                } else {
                    ""
                }
            ),
        });

        print("run child kill");
        let _ = child.kill();

        crossterm::terminal::disable_raw_mode()?;

        Ok(InvokeOutput {
            output: OutputKind::Json(output),
        })
    }

    pub async fn invoke3(&self, mut updates: impl Write) -> anyhow::Result<InvokeOutput> {
        const LINE_COUNT: usize = 1024;
        // Enable raw mode
        crossterm::terminal::enable_raw_mode()?;
    
        // Create a default terminal size using crossterm
        let pty_size = Self::get_terminal_size().ok().unwrap();
    
        // Open a new pseudoterminal
        let pty_pair = open_pty(&pty_size)?;

    
        // Create a command builder for the shell command
        let shell: String = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_string());
        let mut cmd_builder = CommandBuilder::new(shell);
        cmd_builder.args(["-cli", &self.command]);
        cmd_builder.cwd(std::env::current_dir()?);
    
        // Need to share between tasks
        let child = Arc::new(tokio::sync::Mutex::new(pty_pair.slave.spawn_command(cmd_builder)?));
        let master = Arc::new(tokio::sync::Mutex::new(pty_pair.master.get_async_master_pty()?));
        
        // Set up a channel to coordinate shutdown
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
    
        // Handle output from the command
        let master_clone = Arc::clone(&master);

        let mut stdout_lines: VecDeque<String> = VecDeque::with_capacity(LINE_COUNT);

        // let updates = Arc::new(tokio::sync::Mutex::new(updates));
        // let updates_clone = Arc::clone(&updates);

        let print = |s: &str| {
            // let _ = execute!(
            //     std::io::stdout().lock(),
            //     style::Print(format!("{}\n", s)),
            // );
        };

        let output_handle = tokio::spawn(async move {
            let mut stdout = std::io::stdout();
            let mut buffer = [0u8; 1024];
            
            let output = loop {
                let mut master_guard = master_clone.lock().await;
                // print("waiting for output");
                match tokio::time::timeout(Duration::from_millis(20), master_guard.read(&mut buffer)).await {
                    Ok(Ok(0)) => {
                        print("no more output, breaking out");
                        
                        break Ok(stdout_lines)}, // End of stream
                    Ok(Ok(n)) => {
                        // let updates_guard = updates_clone.lock().await;
                        // updates_guard.write_all(&buffer[..n])?;
                        // updates_guard.flush()?;
                        // print("got output, writing");
                        stdout.write_all(&buffer[..n])?;
                        stdout.flush()?;

                        if let Ok(text) = std::str::from_utf8(&buffer) {
                            for subline in text.split_inclusive('\n') {
                                if stdout_lines.len() >= LINE_COUNT {
                                    stdout_lines.pop_front();
                                }
                                stdout_lines.push_back(strip_ansi_codes(subline).to_string().trim().to_string());
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("Error reading from PTY: {:?}", e);
                        print("error with reading output");
                        break Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("child error: {}", e)
                        ));
                    }
                    Err(_) => {
                        // print("read timed oucart");
                        continue
                    }
                }
            };
    
            // Signal that we're done reading output
            print("signal output reading exit");
            let _ = tx_clone.send(()).await;
            return output
        });
    
        // Handle input from the user using crossterm
        let master_clone = Arc::clone(&master);
        let input_handle = tokio::spawn(async move {
            loop {
                // print("new input read iteration");
                tokio::select! {
                    // Check if the process is done
                    Some(_) = rx.recv() => {
                        print("break input - signal received");
                        
                        break
                    },
    
                    // Use a separate task to poll for events to avoid blocking
                    event = tokio::task::spawn_blocking(|| crossterm::event::read()) => {
                        // print("event detected");
                        match event {
                            Ok(Ok(crossterm::event::Event::Key(key))) => {
                                // Convert the key event to bytes and send to the PTY
                                // print("read key input");
                                let bytes = Self::key_event_to_bytes(key);
                                if !bytes.is_empty() {
                                    // print("converted to bytes, locking for write to pty stdin");
                                    if let Err(e) = master_clone.lock().await.write_all(&bytes).await {
                                        print("error writing to pty stdin");
                                        eprintln!("Error writing to PTY: {:?}", e);
                                        break;
                                    }
                                    // print("done writing to pty stdin, unlocking");
                                }
                            }
                            Ok(Ok(crossterm::event::Event::Resize(cols, rows))) => {
                                // Handle terminal resize
                                print("resize event");
                                let size = PtySize {
                                    rows: rows as u16,
                                    cols: cols as u16,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                };
                                let _ = master_clone.lock().await.resize(size);
                            }
                            Ok(Err(e)) => {
                                print("event error");
                                eprintln!("Error reading event: {:?}", e);
                                break;
                            }
                            Err(e) => {
                                print("task error");
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
        print("waiting for all output");
        let stdout_lines = output_handle.await??;
        
        // Signal the input handler to stop
        print("output done, signal exit");
        let _ = tx.send(()).await;

        // Clean out any remaining events
        while crossterm::event::poll(Duration::from_millis(0))? {
            let _ = crossterm::event::read();
        }
        
        // Wait for the input handler to complete
        print("wait for input handler to exit");
        let _ = input_handle.await;
    
        // Wait for the child process to exit
        print("getting exit status");
        let mut child_guard = child.lock().await;
        let exit_status = child_guard.wait()?;
    
        // Disable raw mode
        crossterm::terminal::disable_raw_mode()?;
    
        let stdout = stdout_lines.into_iter().collect::<String>();
        let output = serde_json::json!({
            "exit_status": exit_status.exit_code().to_string(),
            "stdout": format!(
                "{}{}",
                truncate_safe(&stdout, MAX_TOOL_RESPONSE_SIZE / 3),
                if stdout.len() > MAX_TOOL_RESPONSE_SIZE / 3 {
                    " ... truncated"
                } else {
                    ""
                }
            ),
        });
    
        Ok(InvokeOutput {
            output: OutputKind::Json(output),
        })
    }

    pub fn queue_description(&self, updates: &mut impl Write) -> Result<()> {
        queue!(updates, style::Print("I will run the following shell command: "),)?;

        // TODO: Could use graphemes for a better heuristic
        if self.command.len() > 20 {
            queue!(updates, style::Print("\n"),)?;
        }

        Ok(queue!(
            updates,
            style::SetForegroundColor(Color::Green),
            style::Print(&self.command),
            style::Print("\n\n"),
            style::ResetColor
        )?)
    }

    pub async fn validate(&mut self, _ctx: &Context) -> Result<()> {
        // TODO: probably some small amount of PATH checking
        Ok(())
    }
}

pub struct CommandResult {
    pub exit_status: Option<i32>,
    /// Truncated stdout
    pub stdout: String,
    /// Truncated stderr
    pub stderr: String,
}

/// Run a bash command.
/// # Arguments
/// * `max_result_size` - max size of output streams, truncating if required
/// * `updates` - output stream to push informational messages about the progress
/// # Returns
/// A [`CommandResult`]
pub async fn run_command<W: Write>(
    command: &str,
    max_result_size: usize,
    mut updates: Option<W>,
) -> Result<CommandResult> {
    // We need to maintain a handle on stderr and stdout, but pipe it to the terminal as well
    let mut child = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err_with(|| format!("Unable to spawn command '{}'", command))?;

    let stdout_final: String;
    let stderr_final: String;
    let exit_status: ExitStatus;

    // Buffered output vs all-at-once
    if let Some(u) = updates.as_mut() {
        let stdout = child.stdout.take().unwrap();
        let stdout = tokio::io::BufReader::new(stdout);
        let mut stdout = stdout.lines();

        let stderr = child.stderr.take().unwrap();
        let stderr = tokio::io::BufReader::new(stderr);
        let mut stderr = stderr.lines();

        const LINE_COUNT: usize = 1024;
        let mut stdout_buf = VecDeque::with_capacity(LINE_COUNT);
        let mut stderr_buf = VecDeque::with_capacity(LINE_COUNT);

        let mut stdout_done = false;
        let mut stderr_done = false;
        exit_status = loop {
            tokio::select! {
                biased;
                line = stdout.next_line(), if !stdout_done => match line {
                    Ok(Some(line)) => {
                        writeln!(u, "{line}")?;
                        if stdout_buf.len() >= LINE_COUNT {
                            stdout_buf.pop_front();
                        }
                        stdout_buf.push_back(line);
                    },
                    Ok(None) => stdout_done = true,
                    Err(err) => error!(%err, "Failed to read stdout of child process"),
                },
                line = stderr.next_line(), if !stderr_done => match line {
                    Ok(Some(line)) => {
                        writeln!(u, "{line}")?;
                        if stderr_buf.len() >= LINE_COUNT {
                            stderr_buf.pop_front();
                        }
                        stderr_buf.push_back(line);
                    },
                    Ok(None) => stderr_done = true,
                    Err(err) => error!(%err, "Failed to read stderr of child process"),
                },
                exit_status = child.wait() => {
                    break exit_status;
                },
            };
        }
        .wrap_err_with(|| format!("No exit status for '{}'", command))?;

        u.flush()?;

        stdout_final = stdout_buf.into_iter().collect::<Vec<_>>().join("\n");
        stderr_final = stderr_buf.into_iter().collect::<Vec<_>>().join("\n");
    } else {
        // Take output all at once since we are not reporting anything in real time
        //
        // NOTE: If we don't split this logic, then any writes to stdout while calling
        // this function concurrently may cause the piped child output to be ignored

        let output = child
            .wait_with_output()
            .await
            .wrap_err_with(|| format!("No exit status for '{}'", command))?;

        exit_status = output.status;
        stdout_final = from_utf8(&output.stdout).unwrap_or_default().to_string();
        stderr_final = from_utf8(&output.stderr).unwrap_or_default().to_string();
    }

    Ok(CommandResult {
        exit_status: exit_status.code(),
        stdout: format!(
            "{}{}",
            truncate_safe(&stdout_final, max_result_size),
            if stdout_final.len() > max_result_size {
                " ... truncated"
            } else {
                ""
            }
        ),
        stderr: format!(
            "{}{}",
            truncate_safe(&stderr_final, max_result_size),
            if stderr_final.len() > max_result_size {
                " ... truncated"
            } else {
                ""
            }
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "todo: fix failing on musl for some reason"]
    #[tokio::test]
    async fn test_execute_bash_tool() {
        let mut stdout = std::io::stdout();

        // Verifying stdout
        let v = serde_json::json!({
            "command": "echo Hello, world!",
        });
        let out = serde_json::from_value::<ExecuteBash>(v)
            .unwrap()
            .invoke(&mut stdout)
            .await
            .unwrap();

        if let OutputKind::Json(json) = out.output {
            assert_eq!(json.get("exit_status").unwrap(), &0.to_string());
            assert_eq!(json.get("stdout").unwrap(), "Hello, world!");
            assert_eq!(json.get("stderr").unwrap(), "");
        } else {
            panic!("Expected JSON output");
        }

        // Verifying stderr
        let v = serde_json::json!({
            "command": "echo Hello, world! 1>&2",
        });
        let out = serde_json::from_value::<ExecuteBash>(v)
            .unwrap()
            .invoke(&mut stdout)
            .await
            .unwrap();

        if let OutputKind::Json(json) = out.output {
            assert_eq!(json.get("exit_status").unwrap(), &0.to_string());
            assert_eq!(json.get("stdout").unwrap(), "");
            assert_eq!(json.get("stderr").unwrap(), "Hello, world!");
        } else {
            panic!("Expected JSON output");
        }

        // Verifying exit code
        let v = serde_json::json!({
            "command": "exit 1",
            "interactive": false
        });
        let out = serde_json::from_value::<ExecuteBash>(v)
            .unwrap()
            .invoke(&mut stdout)
            .await
            .unwrap();
        if let OutputKind::Json(json) = out.output {
            assert_eq!(json.get("exit_status").unwrap(), &1.to_string());
            assert_eq!(json.get("stdout").unwrap(), "");
            assert_eq!(json.get("stderr").unwrap(), "");
        } else {
            panic!("Expected JSON output");
        }
    }

    #[test]
    fn test_requires_acceptance_for_readonly_commands() {
        let cmds = &[
            // Safe commands
            ("ls ~", false),
            ("ls -al ~", false),
            ("pwd", false),
            ("echo 'Hello, world!'", false),
            ("which aws", false),
            // Potentially dangerous readonly commands
            ("echo hi > myimportantfile", true),
            ("ls -al >myimportantfile", true),
            ("echo hi 2> myimportantfile", true),
            ("echo hi >> myimportantfile", true),
            ("echo $(rm myimportantfile)", true),
            ("echo `rm myimportantfile`", true),
            ("echo hello && rm myimportantfile", true),
            ("echo hello&&rm myimportantfile", true),
            ("ls nonexistantpath || rm myimportantfile", true),
            ("echo myimportantfile | xargs rm", true),
            ("echo myimportantfile|args rm", true),
            ("echo <(rm myimportantfile)", true),
            ("cat <<< 'some string here' > myimportantfile", true),
            ("echo '\n#!/usr/bin/env bash\necho hello\n' > myscript.sh", true),
            ("cat <<EOF > myimportantfile\nhello world\nEOF", true),
            // Safe piped commands
            ("find . -name '*.rs' | grep main", false),
            ("ls -la | grep .git", false),
            ("cat file.txt | grep pattern | head -n 5", false),
            // Unsafe piped commands
            ("find . -name '*.rs' | rm", true),
            ("ls -la | grep .git | rm -rf", true),
            ("echo hello | sudo rm -rf /", true),
            // `find` command arguments
            ("find important-dir/ -exec rm {} \\;", true),
            ("find . -name '*.c' -execdir gcc -o '{}.out' '{}' \\;", true),
            ("find important-dir/ -delete", true),
            ("find important-dir/ -name '*.txt'", false),
        ];
        for (cmd, expected) in cmds {
            let tool = serde_json::from_value::<ExecuteBash>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            assert_eq!(
                tool.requires_acceptance(),
                *expected,
                "expected command: `{}` to have requires_acceptance: `{}`",
                cmd,
                expected
            );
        }
    }
}
