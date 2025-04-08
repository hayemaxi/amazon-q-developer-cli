use std::collections::HashMap;
use std::path::{
    Path,
    PathBuf,
};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use eyre::{
    Result,
    eyre,
};
use fig_os_shim::Context;
use fig_util::directories;
use glob::glob;
use regex::Regex;
use serde::{
    Deserialize,
    Serialize,
};

use crate::cli::chat::hooks::HookConfig;

use super::hooks::{Hook, HookType};
use super::tools::execute_bash::run_command;

pub const AMAZONQ_FILENAME: &str = "AmazonQ.md";

/// Configuration for context files, containing paths to include in the context.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextConfig {
    /// List of file paths or glob patterns to include in the context.
    pub paths: Option<Vec<String>>,
    pub hooks: Option<HookConfig>,
}

#[allow(dead_code)]
/// Manager for context files and profiles.
#[derive(Debug, Clone)]
pub struct ContextManager {
    ctx: Arc<Context>,

    /// Global context configuration that applies to all profiles.
    pub global_config: ContextConfig,

    /// Name of the current active profile.
    pub current_profile: String,

    /// Context configuration for the current profile.
    pub profile_config: ContextConfig,

    hook_executor: HookExecutor,
}

#[allow(dead_code)]
impl ContextManager {
    /// Create a new ContextManager with default settings.
    ///
    /// This will:
    /// 1. Create the necessary directories if they don't exist
    /// 2. Load the global configuration
    /// 3. Load the default profile configuration
    ///
    /// # Returns
    /// A Result containing the new ContextManager or an error
    pub async fn new(ctx: Arc<Context>) -> Result<Self> {
        let profiles_dir = directories::chat_profiles_dir(&ctx)?;

        ctx.fs().create_dir_all(&profiles_dir).await?;

        let global_config = load_global_config(&ctx).await?;
        let current_profile = "default".to_string();
        let profile_config = load_profile_config(&ctx, &current_profile).await?;

        Ok(Self {
            ctx,
            global_config,
            current_profile,
            profile_config,
            hook_executor: HookExecutor::new(),
        })
    }

    /// Save the current configuration to disk.
    ///
    /// # Arguments
    /// * `global` - If true, save the global configuration; otherwise, save the current profile
    ///   configuration
    ///
    /// # Returns
    /// A Result indicating success or an error
    async fn save_config(&self, global: bool) -> Result<()> {
        if global {
            let global_path = directories::chat_global_context_path(&self.ctx)?;
            let contents = serde_json::to_string_pretty(&self.global_config)
                .map_err(|e| eyre!("Failed to serialize global configuration: {}", e))?;

            self.ctx.fs().write(&global_path, contents).await?;
        } else {
            let profile_path = profile_context_path(&self.ctx, &self.current_profile)?;
            if let Some(parent) = profile_path.parent() {
                self.ctx.fs().create_dir_all(parent).await?;
            }
            let contents = serde_json::to_string_pretty(&self.profile_config)
                .map_err(|e| eyre!("Failed to serialize profile configuration: {}", e))?;

            self.ctx.fs().write(&profile_path, contents).await?;
        }

        Ok(())
    }

    /// Add paths to the context configuration.
    ///
    /// # Arguments
    /// * `paths` - List of paths to add
    /// * `global` - If true, add to global configuration; otherwise, add to current profile
    ///   configuration
    /// * `force` - If true, skip validation that the path exists
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn add_paths(&mut self, paths: Vec<String>, global: bool, force: bool) -> Result<()> {
        // Get reference to the appropriate config
        let config = if global {
            &mut self.global_config
        } else {
            &mut self.profile_config
        };

        if config.paths.is_none() {
            config.paths = Some(Vec::new());
        }
        let curr_paths = config.paths.as_mut().unwrap();

        // Validate paths exist before adding them
        if !force {
            let mut context_files = Vec::new();

            // Check each path to make sure it exists or matches at least one file
            for path in &paths {
                // We're using a temporary context_files vector just for validation
                // Pass is_validation=true to ensure we error if glob patterns don't match any files
                match process_path(&self.ctx, path, &mut context_files, false, true).await {
                    Ok(_) => {}, // Path is valid
                    Err(e) => return Err(eyre!("Invalid path '{}': {}. Use --force to add anyway.", path, e)),
                }
            }
        }

        // Add each path, checking for duplicates
        for path in paths {
            if curr_paths.contains(&path) {
                return Err(eyre!("Path '{}' already exists in the context", path));
            }
            curr_paths.push(path);
        }

        // Save the updated configuration
        self.save_config(global).await?;

        Ok(())
    }

    /// Remove paths from the context configuration.
    ///
    /// # Arguments
    /// * `paths` - List of paths to remove
    /// * `global` - If true, remove from global configuration; otherwise, remove from current
    ///   profile configuration
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn remove_paths(&mut self, paths: Vec<String>, global: bool) -> Result<()> {
        // Get reference to the appropriate config
        let config = if global {
            &mut self.global_config
        } else {
            &mut self.profile_config
        };

        // Track if any paths were removed
        let mut removed_any = false;

        // Remove each path if it exists
        if let Some(curr_paths) = config.paths.as_mut() {
            for path in paths {
                let original_len = curr_paths.len();
                curr_paths.retain(|p| *p != *path);

                if curr_paths.len() < original_len {
                    removed_any = true;
                }
            }
        }

        if !removed_any {
            return Err(eyre!("None of the specified paths were found in the context"));
        }

        // Save the updated configuration
        self.save_config(global).await?;

        Ok(())
    }

    /// List all available profiles.
    ///
    /// # Returns
    /// A Result containing a vector of profile names, with "default" always first
    pub async fn list_profiles(&self) -> Result<Vec<String>> {
        let mut profiles = Vec::new();

        // Always include default profile
        profiles.push("default".to_string());

        // Read profile directory and extract profile names
        let profiles_dir = directories::chat_profiles_dir(&self.ctx)?;
        if profiles_dir.exists() {
            let mut read_dir = self.ctx.fs().read_dir(&profiles_dir).await?;
            while let Some(entry) = read_dir.next_entry().await? {
                let path = entry.path();
                if let (true, Some(name)) = (path.is_dir(), path.file_name()) {
                    if name != "default" {
                        profiles.push(name.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Sort non-default profiles alphabetically
        if profiles.len() > 1 {
            profiles[1..].sort();
        }

        Ok(profiles)
    }

    /// Clear all paths from the context configuration.
    ///
    /// # Arguments
    /// * `global` - If true, clear global configuration; otherwise, clear current profile
    ///   configuration
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn clear(&mut self, global: bool) -> Result<()> {
        // Clear the appropriate config
        if global {
            self.global_config.paths.as_mut().map(|p| p.clear());
        } else {
            self.profile_config.paths.as_mut().map(|p| p.clear());
        }

        // Save the updated configuration
        self.save_config(global).await?;

        Ok(())
    }

    /// Create a new profile.
    ///
    /// # Arguments
    /// * `name` - Name of the profile to create
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn create_profile(&self, name: &str) -> Result<()> {
        validate_profile_name(name)?;

        // Check if profile already exists
        let profile_path = profile_context_path(&self.ctx, name)?;
        if profile_path.exists() {
            return Err(eyre!("Profile '{}' already exists", name));
        }

        // Create empty profile configuration
        let config = ContextConfig::default();
        let contents = serde_json::to_string_pretty(&config)
            .map_err(|e| eyre!("Failed to serialize profile configuration: {}", e))?;

        // Create the file
        if let Some(parent) = profile_path.parent() {
            self.ctx.fs().create_dir_all(parent).await?;
        }
        self.ctx.fs().write(&profile_path, contents).await?;

        Ok(())
    }

    /// Delete a profile.
    ///
    /// # Arguments
    /// * `name` - Name of the profile to delete
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn delete_profile(&self, name: &str) -> Result<()> {
        if name == "default" {
            return Err(eyre!("Cannot delete the default profile"));
        } else if name == self.current_profile {
            return Err(eyre!(
                "Cannot delete the active profile. Switch to another profile first"
            ));
        }

        let profile_path = profile_dir_path(&self.ctx, name)?;
        if !profile_path.exists() {
            return Err(eyre!("Profile '{}' does not exist", name));
        }

        self.ctx.fs().remove_dir_all(&profile_path).await?;

        Ok(())
    }

    /// Rename a profile.
    ///
    /// # Arguments
    /// * `old_name` - Current name of the profile
    /// * `new_name` - New name for the profile
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn rename_profile(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        // Validate profile names
        if old_name == "default" {
            return Err(eyre!("Cannot rename the default profile"));
        }
        if new_name == "default" {
            return Err(eyre!("Cannot rename to 'default' as it's a reserved profile name"));
        }

        validate_profile_name(new_name)?;

        let old_profile_path = profile_dir_path(&self.ctx, old_name)?;
        if !old_profile_path.exists() {
            return Err(eyre!("Profile '{}' not found", old_name));
        }

        let new_profile_path = profile_dir_path(&self.ctx, new_name)?;
        if new_profile_path.exists() {
            return Err(eyre!("Profile '{}' already exists", new_name));
        }

        self.ctx.fs().rename(&old_profile_path, &new_profile_path).await?;

        // If the current profile is being renamed, update the current_profile field
        if self.current_profile == old_name {
            self.current_profile = new_name.to_string();
            self.profile_config = load_profile_config(&self.ctx, new_name).await?;
        }

        Ok(())
    }

    /// Switch to a different profile.
    ///
    /// # Arguments
    /// * `name` - Name of the profile to switch to
    ///
    /// # Returns
    /// A Result indicating success or an error
    pub async fn switch_profile(&mut self, name: &str) -> Result<()> {
        validate_profile_name(name)?;

        // Special handling for default profile - it always exists
        if name == "default" {
            // Load the default profile configuration
            let profile_config = load_profile_config(&self.ctx, name).await?;

            // Update the current profile
            self.current_profile = name.to_string();
            self.profile_config = profile_config;

            return Ok(());
        }

        // Check if profile exists
        let profile_path = profile_context_path(&self.ctx, name)?;
        if !profile_path.exists() {
            return Err(eyre!("Profile '{}' does not exist. Use 'create' to create it", name));
        }

        // Update the current profile
        self.current_profile = name.to_string();
        self.profile_config = load_profile_config(&self.ctx, name).await?;

        Ok(())
    }

    /// Get all context files (global + profile-specific).
    ///
    /// This method:
    /// 1. Processes all paths in the global and profile configurations
    /// 2. Expands glob patterns to include matching files
    /// 3. Reads the content of each file
    /// 4. Returns a vector of (filename, content) pairs
    ///
    /// # Arguments
    /// * `force` - If true, include paths that don't exist yet
    ///
    /// # Returns
    /// A Result containing a vector of (filename, content) pairs or an error
    pub async fn get_context_files(&self, force: bool) -> Result<Vec<(String, String)>> {
        let mut context_files = Vec::new();

        // Process global paths first
        if let Some(paths) = &self.global_config.paths {
            for path in paths {
                // Use is_validation=false for get_context_files to handle non-matching globs gracefully
                process_path(&self.ctx, path, &mut context_files, force, false).await?;
            }
        }

        // Then process profile-specific paths
        if let Some(paths) = &self.profile_config.paths {
                for path in paths {
                // Use is_validation=false for get_context_files to handle non-matching globs gracefully
                process_path(&self.ctx, path, &mut context_files, force, false).await?;
            }
        }

        Ok(context_files)
    }

    pub async fn run_conversation_start_hooks(&self) -> Vec<(String, Result<String>, Duration)> {
        let mut hooks: Vec<&Hook> = Vec::new();

        self.global_config.hooks.as_ref()
            .and_then(|hooks| hooks.conversation_start.as_ref())
            .map(|h| hooks.extend(h));
    

        self.profile_config.hooks.as_ref()
            .and_then(|hooks| hooks.conversation_start.as_ref())
            .map(|h| {
                hooks.extend(h)
            });

        self.hook_executor.run_hooks(hooks, true).await
    }

    pub async fn run_per_prompt_hooks(&self) -> Vec<(String, Result<String>, Duration)> {
        let mut hooks: Vec<&Hook> = Vec::new();

        self.global_config.hooks.as_ref()
            .and_then(|hooks| hooks.per_prompt.as_ref())
            .map(|h| hooks.extend(h));
    

        self.profile_config.hooks.as_ref()
            .and_then(|hooks| hooks.per_prompt.as_ref())
            .map(|h| {
                hooks.extend(h)
            });

        self.hook_executor.run_hooks(hooks, false).await
    }
}

#[derive(Debug, Clone)]
pub struct HookExecutor {
    cache_conversation_start: Arc<RwLock<HashMap<String, (String, Instant)>>>,
    cache_per_prompt: Arc<RwLock<HashMap<String, (String, Instant)>>>,
    disabled_hooks: HashMap<String, bool>,
}

impl HookExecutor {
    pub fn new() -> Self {
        Self {
            cache_conversation_start: Arc::new(RwLock::new(HashMap::new())),
            cache_per_prompt: Arc::new(RwLock::new(HashMap::new())),
            disabled_hooks: HashMap::new(),
        }
    }

    pub async fn run_hooks(&self, hooks: Vec<&Hook>, conversation_start: bool) -> Vec<(String, Result<String>, Duration)> {
        let mut futures = Vec::new();
        for hook in hooks {
            if !hook.enabled.unwrap_or(true) || self.disabled_hooks.get(&hook.name).is_some_and(|b| *b) {
                continue;
            }
            futures.push(self.execute_hook(hook, conversation_start));
        }
    
        futures::future::join_all(futures).await
    }

    async fn execute_hook(&self, hook: &Hook, conversation_start: bool) -> (String, Result<String>, Duration) {
        let start_time = Instant::now();

        // Check cache for existing value
        if let Some(cached_value) = self.get(&hook.name, conversation_start) {
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
            self.insert(&hook.name, conversation_start, value.clone(), Instant::now() + Duration::from_secs(hook.cache_ttl_seconds.unwrap_or(0)));
        }

        (hook.name.clone(), result, start_time.elapsed())
    }

    async fn execute_inline_hook(&self, hook: &Hook) -> Result<String> {
        let command = hook.command.as_ref().expect("command required for inline hooks");
    
        let result = run_command(
            command,
            hook.max_output_size.unwrap_or(1024*10), 
            None::<std::io::Stdout>
        ).await?;
    
        let exit_code = result.0.unwrap_or_default();
        match exit_code {
            0 => Ok(result.1),
            _ => Err(eyre!("Hook {} failed with exit code {}", hook.name, exit_code)),
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

    fn get(&self, name: &str, conversation_start: bool) -> Option<String> {
        let cache = if conversation_start {
            &self.cache_conversation_start
        } else {
            &self.cache_per_prompt
        };

        cache.read().unwrap().get(name).and_then(|(value, expiry)| {
            if Instant::now() < *expiry {
                Some(value.clone())
            } else {
                None
            }
        })
    }

    fn insert(&self, name: &str, conversation_start: bool, output: String, expiry: Instant) {
        let cache = if conversation_start {
            &self.cache_conversation_start
        } else {
            &self.cache_per_prompt
        };

        cache.write().unwrap().insert(name.to_string(), (output, expiry));
    }
}

fn profile_dir_path(ctx: &Context, profile_name: &str) -> Result<PathBuf> {
    Ok(directories::chat_profiles_dir(ctx)?.join(profile_name))
}

/// Path to the context config file for `profile_name`.
fn profile_context_path(ctx: &Context, profile_name: &str) -> Result<PathBuf> {
    Ok(directories::chat_profiles_dir(ctx)?
        .join(profile_name)
        .join("context.json"))
}

/// Load the global context configuration.
///
/// If the global configuration file doesn't exist, returns a default configuration.
async fn load_global_config(ctx: &Context) -> Result<ContextConfig> {
    let global_path = directories::chat_global_context_path(&ctx)?;
    if ctx.fs().exists(&global_path) {
        let contents = ctx.fs().read_to_string(&global_path).await?;
        let config: ContextConfig =
            serde_json::from_str(&contents).map_err(|e| eyre!("Failed to parse global configuration: {}", e))?;
        Ok(config)
    } else {
        // Return default global configuration with predefined paths
        Ok(ContextConfig {
            paths: Some(vec![
                ".amazonq/rules/**/*.md".to_string(),
                "README.md".to_string(),
                AMAZONQ_FILENAME.to_string(),
            ]),
            hooks: None,
        })
    }
}

/// Load a profile's context configuration.
///
/// If the profile configuration file doesn't exist, creates a default configuration.
async fn load_profile_config(ctx: &Context, profile_name: &str) -> Result<ContextConfig> {
    let profile_path = profile_context_path(ctx, profile_name)?;
    if ctx.fs().exists(&profile_path) {
        let contents = ctx.fs().read_to_string(&profile_path).await?;
        let config: ContextConfig =
            serde_json::from_str(&contents).map_err(|e| eyre!("Failed to parse profile configuration: {}", e))?;
        Ok(config)
    } else {
        // Return empty configuration for new profiles
        Ok(ContextConfig::default())
    }
}

/// Process a path, handling glob patterns and file types.
///
/// This method:
/// 1. Expands the path (handling ~ for home directory)
/// 2. If the path contains glob patterns, expands them
/// 3. For each resulting path, adds the file to the context collection
/// 4. Handles directories by including all files in the directory (non-recursive)
/// 5. With force=true, includes paths that don't exist yet
///
/// # Arguments
/// * `path` - The path to process
/// * `context_files` - The collection to add files to
/// * `force` - If true, include paths that don't exist yet
/// * `is_validation` - If true, error when glob patterns don't match; if false, silently skip
///
/// # Returns
/// A Result indicating success or an error
async fn process_path(
    ctx: &Context,
    path: &str,
    context_files: &mut Vec<(String, String)>,
    force: bool,
    is_validation: bool,
) -> Result<()> {
    // Expand ~ to home directory
    let expanded_path = if path.starts_with('~') {
        if let Some(home_dir) = ctx.env().home() {
            home_dir.join(&path[2..]).to_string_lossy().to_string()
        } else {
            return Err(eyre!("Could not determine home directory"));
        }
    } else {
        path.to_string()
    };

    // Handle absolute, relative paths, and glob patterns
    let full_path = if expanded_path.starts_with('/') {
        expanded_path
    } else {
        ctx.env()
            .current_dir()?
            .join(&expanded_path)
            .to_string_lossy()
            .to_string()
    };

    // Required in chroot testing scenarios so that we can use `Path::exists`.
    let full_path = ctx.fs().chroot_path_str(full_path);

    // Check if the path contains glob patterns
    if full_path.contains('*') || full_path.contains('?') || full_path.contains('[') {
        // Expand glob pattern
        match glob(&full_path) {
            Ok(entries) => {
                let mut found_any = false;

                for entry in entries {
                    match entry {
                        Ok(path) => {
                            if path.is_file() {
                                add_file_to_context(ctx, &path, context_files).await?;
                                found_any = true;
                            }
                        },
                        Err(e) => return Err(eyre!("Glob error: {}", e)),
                    }
                }

                if !found_any && !force && is_validation {
                    // When validating paths (e.g., for /context add), error if no files match
                    return Err(eyre!("No files found matching glob pattern '{}'", full_path));
                }
                // When just showing expanded files (e.g., for /context show --expand),
                // silently skip non-matching patterns (don't add anything to context_files)
            },
            Err(e) => return Err(eyre!("Invalid glob pattern '{}': {}", full_path, e)),
        }
    } else {
        // Regular path
        let path = Path::new(&full_path);
        if path.exists() {
            if path.is_file() {
                add_file_to_context(ctx, path, context_files).await?;
            } else if path.is_dir() {
                // For directories, add all files in the directory (non-recursive)
                let mut read_dir = ctx.fs().read_dir(path).await?;
                while let Some(entry) = read_dir.next_entry().await? {
                    let path = entry.path();
                    if path.is_file() {
                        add_file_to_context(ctx, &path, context_files).await?;
                    }
                }
            }
        } else if !force && is_validation {
            // When validating paths (e.g., for /context add), error if the path doesn't exist
            return Err(eyre!("Path '{}' does not exist", full_path));
        } else if force {
            // When using --force, we'll add the path even though it doesn't exist
            // This allows users to add paths that will exist in the future
            context_files.push((full_path.clone(), format!("(Path '{}' does not exist yet)", full_path)));
        }
        // When just showing expanded files (e.g., for /context show --expand),
        // silently skip non-existent paths if is_validation is false
    }

    Ok(())
}

/// Add a file to the context collection.
///
/// This method:
/// 1. Reads the content of the file
/// 2. Adds the (filename, content) pair to the context collection
///
/// # Arguments
/// * `path` - The path to the file
/// * `context_files` - The collection to add the file to
///
/// # Returns
/// A Result indicating success or an error
async fn add_file_to_context(ctx: &Context, path: &Path, context_files: &mut Vec<(String, String)>) -> Result<()> {
    let filename = path.to_string_lossy().to_string();
    let content = ctx.fs().read_to_string(path).await?;
    context_files.push((filename, content));
    Ok(())
}

/// Validate a profile name.
///
/// Profile names can only contain alphanumeric characters, hyphens, and underscores.
///
/// # Arguments
/// * `name` - Name to validate
///
/// # Returns
/// A Result indicating if the name is valid
fn validate_profile_name(name: &str) -> Result<()> {
    // Check if name is empty
    if name.is_empty() {
        return Err(eyre!("Profile name cannot be empty"));
    }

    // Check if name contains only allowed characters and starts with an alphanumeric character
    let re = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$").unwrap();
    if !re.is_match(name) {
        return Err(eyre!(
            "Profile name must start with an alphanumeric character and can only contain alphanumeric characters, hyphens, and underscores"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a test ContextManager with Context
    pub async fn create_test_context_manager() -> Result<ContextManager> {
        let ctx = Context::builder().with_test_home().await.unwrap().build_fake();
        let manager = ContextManager::new(ctx).await?;
        Ok(manager)
    }

    #[tokio::test]
    async fn test_validate_profile_name() {
        // Test valid names
        assert!(validate_profile_name("valid").is_ok());
        assert!(validate_profile_name("valid-name").is_ok());
        assert!(validate_profile_name("valid_name").is_ok());
        assert!(validate_profile_name("valid123").is_ok());
        assert!(validate_profile_name("1valid").is_ok());
        assert!(validate_profile_name("9test").is_ok());

        // Test invalid names
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("invalid/name").is_err());
        assert!(validate_profile_name("invalid.name").is_err());
        assert!(validate_profile_name("invalid name").is_err());
        assert!(validate_profile_name("_invalid").is_err());
        assert!(validate_profile_name("-invalid").is_err());
    }

    #[tokio::test]
    async fn test_profile_ops() -> Result<()> {
        let mut manager = create_test_context_manager().await?;
        let ctx = Arc::clone(&manager.ctx);

        assert_eq!(manager.current_profile, "default");

        // Create ops
        manager.create_profile("test_profile").await?;
        assert!(profile_context_path(&ctx, "test_profile")?.exists());
        assert!(manager.create_profile("test_profile").await.is_err());
        manager.create_profile("alt").await?;

        // Listing
        let profiles = manager.list_profiles().await?;
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"test_profile".to_string()));
        assert!(profiles.contains(&"alt".to_string()));

        // Switching
        manager.switch_profile("test_profile").await?;
        assert!(manager.switch_profile("notexists").await.is_err());

        // Renaming
        manager.rename_profile("alt", "renamed").await?;
        assert!(!profile_context_path(&ctx, "alt")?.exists());
        assert!(profile_context_path(&ctx, "renamed")?.exists());

        // Delete ops
        assert!(manager.delete_profile("test_profile").await.is_err());
        manager.switch_profile("default").await?;
        manager.delete_profile("test_profile").await?;
        assert!(!profile_context_path(&ctx, "test_profile")?.exists());
        assert!(manager.delete_profile("test_profile").await.is_err());
        assert!(manager.delete_profile("default").await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_path_ops() -> Result<()> {
        let mut manager = create_test_context_manager().await?;
        let ctx = Arc::clone(&manager.ctx);

        // Create some test files for matching.
        ctx.fs().create_dir_all("test").await?;
        ctx.fs().write("test/p1.md", "p1").await?;
        ctx.fs().write("test/p2.md", "p2").await?;

        assert!(
            manager.get_context_files(false).await?.is_empty(),
            "no files should be returned for an empty profile when force is false"
        );
        assert_eq!(
            manager.get_context_files(true).await?.len(),
            2,
            "default non-glob global files should be included when force is true"
        );

        manager.add_paths(vec!["test/*.md".to_string()], false, false).await?;
        let files = manager.get_context_files(false).await?;
        assert!(files[0].0.ends_with("p1.md"));
        assert_eq!(files[0].1, "p1");
        assert!(files[1].0.ends_with("p2.md"));
        assert_eq!(files[1].1, "p2");

        assert!(
            manager
                .add_paths(vec!["test/*.txt".to_string()], false, false)
                .await
                .is_err(),
            "adding a glob with no matching and without force should fail"
        );

        Ok(())
    }
}
