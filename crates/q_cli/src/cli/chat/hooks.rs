use std::{collections::HashMap, io::Write, sync::Arc, time::{Duration, Instant}};

use serde::{
    Deserialize,
    Serialize,
};
use tokio::sync::RwLock;
use eyre::{
    Result,
    eyre,
};

use crossterm::style::Color;
use crossterm::{
    execute,
    queue,
    style,
};

use super::tools::execute_bash::run_command;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookType {
    Inline,
    // Addtional hooks as necessary
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    pub name: String,
    pub r#type: HookType,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub timeout_ms: Option<u64>,
    pub max_output_size: Option<usize>,
    pub cache_ttl_seconds: Option<u64>,
    // Type-specific fields
    pub command: Option<String>,     // For inline hooks
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub conversation_start: Vec<Hook>,
    pub per_prompt: Vec<Hook>,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            conversation_start: Vec::new(),
            per_prompt: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HookExecutor {
    cache_conversation_start: Arc<RwLock<HashMap<String, (String, Instant)>>>,
    cache_per_prompt: Arc<RwLock<HashMap<String, (String, Instant)>>>,
}

impl HookExecutor {
    pub fn new() -> Self {
        Self {
            cache_conversation_start: Arc::new(RwLock::new(HashMap::new())),
            cache_per_prompt: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run_hooks(&self, hooks: Vec<&Hook>, conversation_start: bool, updates: &mut impl Write) -> Vec<(String, Result<String>)> {
        let mut futures = Vec::new();
        // Start hooks
        for hook in hooks {
            if !hook.enabled {
                continue;
            }
            futures.push(self.execute_hook(hook, conversation_start));
        }

        if futures.is_empty() {
            return Vec::new();
        }

        execute!(
            updates,
            style::SetForegroundColor(Color::Green),
            style::Print(format!("\n\nRunning {} hooks . . . ", futures.len())),
        );
    
        // Wait for results
        let results = futures::future::join_all(futures).await;

        // Output time data.
        let total_duration = format!("{:.3}s", results.iter().map(|r| r.2).sum::<Duration>().as_secs_f64());
        queue!(
            updates,
            style::SetForegroundColor(Color::Green),
            style::Print(format!("completed in {} ms\n", total_duration)),
            style::SetForegroundColor(Color::Reset),
        );

        for r in &results {
            match &r.1 {
                Err(e) => {
                    queue!(
                        updates,
                        style::SetForegroundColor(Color::Red),
                        style::Print(format!("Hook `{}` failed: \n{}\n", r.0, e)),
                        style::SetForegroundColor(Color::Reset),
                    );
                },
                _ => ()
            }
        }
        execute!(updates, style::Print("\n"));

        results.into_iter().map(|r| (r.0, r.1)).collect()
    }

    async fn execute_hook(&self, hook: &Hook, conversation_start: bool) -> (String, Result<String>, Duration) {
        let start_time = Instant::now();

        // Check cache for existing value
        if let Some(cached_value) = self.get_cache(&hook.name, conversation_start).await {
            return (
                hook.name.clone(),
                Ok(cached_value),
                Duration::from_secs(0),
            );
        }

        // Cache miss or expired - execute hook
        let result = match hook.r#type {
            HookType::Inline => self.execute_inline_hook(hook).await,
        };

        // If execution was successful, update cache
        if let Ok(value) = &result {
            self.insert_cache(&hook.name, conversation_start, value.clone(), Instant::now() + Duration::from_secs(hook.cache_ttl_seconds.unwrap_or(0))).await;
        }

        (hook.name.clone(), result, start_time.elapsed())
    }

    async fn execute_inline_hook(&self, hook: &Hook) -> Result<String> {
        let command = hook.command.as_ref().expect("command required for inline hooks");
        let command_future = run_command(
            command,
            hook.max_output_size.unwrap_or(1024 * 10), 
            None::<std::io::Stdout>
        );
        let timeout = Duration::from_millis(hook.timeout_ms.unwrap_or(10000));

        // Run with timeout
        match tokio::time::timeout(timeout, command_future).await? {
            Ok(result) => {
                let exit_status = result.exit_status.unwrap_or(0);
                if exit_status != 0 {
                    Err(eyre!("command returned non-zero exit code {}, stderr: {}", exit_status, result.stderr))
                } else{
                    Ok(result.stdout)
                }
            },
            Err(_) => {
                Err(eyre!("command timed out after {} ms.", timeout.as_millis()))
            }
        }
    }
    
    // pub async fn execute_conversation_start_hooks(&self) -> Result<Vec<ContextEntry>> {
    //     // Get enabled conversation start hooks
    //     let hooks = self.config_manager.get_conversation_start_hooks();
    //     let mut context_entries = Vec::new();
        
    //     // Create futures for all hooks to run in parallel
    //     let mut futures = Vec::new();
    //     for hook in hooks {
    //         if !self.hook_registry.is_hook_enabled(&hook.name) {
    //             continue;
    //         }
            
    //         let hook_clone = hook.clone();
    //         let self_clone = self.clone();
    //         futures.push(async move {
    //             (hook_clone.name.clone(), self_clone.execute_hook(&hook_clone).await)
    //         });
    //     }
        
    //     // Wait for all hooks to complete
    //     let results = futures::future::join_all(futures).await;
        
    //     // Process results
    //     for (name, result) in results {
    //         match result {
    //             Ok(output) => {
    //                 // Format output as context entry
    //                 let entry = ContextEntry::new(
    //                     format!("hook:{}", name),
    //                     output,
    //                     ContextSource::Hook(name),
    //                 );
    //                 context_entries.push(entry);
    //             }
    //             Err(e) => {
    //                 println!("Hook {} failed: {}", name, e);
    //             }
    //         }
    //     }
        
    //     Ok(context_entries)
    // }

    // pub async fn execute_per_prompt_hooks(&self) -> Result<Vec<ContextEntry>> {
    //     // Similar to execute_conversation_start_hooks but for per-prompt hooks
    //     // Get enabled per-prompt hooks
    //     let hooks = self.config_manager.get_per_prompt_hooks();
    //     let mut context_entries = Vec::new();
        
    //     // Create futures for all hooks to run in parallel
    //     let mut futures = Vec::new();
    //     for hook in hooks {
    //         if !self.hook_registry.is_hook_enabled(&hook.name) {
    //             continue;
    //         }
            
    //         println!("Running hook: {}...", hook.name);
    //         let start_time = Instant::now();
            
    //         match self.execute_hook(hook).await {
    //             Ok(output) => {
    //                 let elapsed = start_time.elapsed();
    //                 println!("Hook {} completed in {:?}", hook.name, elapsed);
                    
    //                 // Format output as context entry
    //                 let entry = ContextEntry::new(
    //                     format!("hook:{}", hook.name),
    //                     output,
    //                     ContextSource::Hook(hook.name.clone()),
    //                 );
    //                 context_entries.push(entry);
    //             }
    //             Err(e) => {
    //                 println!("Hook {} failed: {}", hook.name, e);
    //             }
    //         }
    //     }
        
    //     Ok(context_entries)
    // }

    // async fn execute_inline_hook(&self, hook: &HookConfig) -> Result<String> {
    //     // Check cache first if TTL is set
    //     if let Some(ttl) = hook.cache_ttl_seconds {
    //         if let Some(cached_result) = self.cache.get(&hook.name) {
    //             if cached_result.timestamp.elapsed().as_secs() < ttl {
    //                 return Ok(cached_result.output.clone());
    //             }
    //         }
    //     }
        
    //     // Execute hook.command in shell using tokio::process::Command
    //     let start = Instant::now();
        
    //     // Create a future with timeout
    //     let timeout_duration = Duration::from_millis(hook.timeout_ms.unwrap_or(5000));
    //     let command_future = async {
    //         Command::new("sh")
    //             .arg("-c")
    //             .arg(&hook.command.as_ref().unwrap())
    //             .output()
    //             .await
    //     };
        
    //     // Run with timeout
    //     let output = match tokio::time::timeout(timeout_duration, command_future).await {
    //         Ok(result) => result?,
    //         Err(_) => {
    //             // Handle timeout based on criticality
    //             match hook.criticality {
    //                 Criticality::Fail => {
    //                     return Err(anyhow!("Hook timed out after {:?}", timeout_duration));
    //                 },
    //                 Criticality::Warn => {
    //                     println!("Warning: Hook '{}' timed out after {:?}", hook.name, timeout_duration);
    //                     return Ok(format!("# Warning: Hook '{}' timed out", hook.name));
    //                 },
    //                 Criticality::Ignore => {
    //                     return Ok(String::new());
    //                 }
    //             }
    //         }
    //     };
            
    //     if !output.status.success() {
    //         // Handle command failure based on criticality
    //         match hook.criticality {
    //             Criticality::Fail => {
    //                 return Err(anyhow!("Command failed with status: {}", output.status));
    //             },
    //             Criticality::Warn => {
    //                 println!("Warning: Hook '{}' failed with status: {}", hook.name, output.status);
    //                 return Ok(format!("# Warning: Hook '{}' failed with status: {}", 
    //                     hook.name, output.status));
    //             },
    //             Criticality::Ignore => {
    //                 return Ok(String::new());
    //             }
    //         }
    //     }
        
    //     // Capture stdout and handle errors
    //     let stdout = String::from_utf8(output.stdout)?;
        
    //     // Apply size limits if configured
    //     if let Some(max_size) = hook.max_output_size {
    //         if stdout.len() > max_size {
    //             return Ok(format!("{}\n... (output truncated, exceeded {} bytes)", 
    //                 &stdout[..max_size], max_size));
    //         }
    //     }
        
    //     Ok(stdout)
    //     // Handle errors and timeouts
    // }

    async fn get_cache(&self, name: &str, conversation_start: bool) -> Option<String> {
        let cache = if conversation_start {
            &self.cache_conversation_start
        } else {
            &self.cache_per_prompt
        };

        cache.read().await.get(name).and_then(|(value, expiry)| {
            if Instant::now() < *expiry {
                Some(value.clone())
            } else {
                None
            }
        })
    }

    async fn insert_cache(&self, name: &str, conversation_start: bool, output: String, expiry: Instant) {
        let cache = if conversation_start {
            &self.cache_conversation_start
        } else {
            &self.cache_per_prompt
        };

        cache.write().await.insert(name.to_string(), (output, expiry));
    }
}

// pub struct InlineHook {
//     common: CommonConfig,
//     command: String,
// }

// impl InlineHook {
//     pub fn new(common: CommonConfig, command: String) -> Self {
//         Self { common, command }
//     }
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct HookManager {
//     hook_config: Rc<HookConfig>,
// }

// impl HookManager {
//     pub fn new(hook_config: HookConfig) -> Self {
//         let hook_config = Rc::new(hook_config);
//         Self {
//             hook_config,
//         }
//     }
    
//     pub fn execute_conversation_start_hooks(&self, hooks: HookConfig) -> &[HookConfig] {
//         &self.conversation_start_hooks
//     }
    
//     pub fn execute_per_prompt_hooks(&self) -> &[HookConfig] {
//         &self.per_prompt_hooks
//     }
// }