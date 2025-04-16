- Feature Name: extra_granular_tool_permissions
- Start Date: 2025-04-15

# Summary

Extend the existing granular tool permissions system to provide finer-grained control over tool operations. This RFC proposes an allow/deny/remove-rule approach for managing permissions, allowing users to specify trusted paths for filesystem operations, trusted commands for shell execution, and trusted service/operation combinations for AWS CLI operations.

# Motivation

The current granular tool permissions system allows users to trust specific tools for the session, but this is still an all-or-nothing approach at the tool level. This presents several limitations:

1. Users who want to trust filesystem operations in specific directories must trust them for the entire filesystem.
2. Users who want to trust specific shell commands (e.g., `git status`) must trust all shell commands.
3. Users working with AWS CLI operations must trust all AWS operations or none.
4. There's no way to create security boundaries around sensitive directories or commands.

In user testing and feedback, we've observed that:
- Users frequently approve the same operations repeatedly, leading to "prompt fatigue"
- Some users resort to trusting entire tools when they only need a subset of functionality
- Users working on multiple projects want different permission levels for different directories

By implementing extra-granular tool permissions, users can create precise security boundaries that match their workflow needs, improving both security and convenience.

# Guide-level explanation

## Core Permission Model

The new permission model introduces three primary commands:

```
/tools allow <tool> [--path=<path>] [--command=<command>] [--service=<service> --operation=<operation>]
/tools deny <tool> [--path=<path>] [--command=<command>] [--service=<service> --operation=<operation>]
/tools remove-rule <tool> [--path=<path>] [--command=<command>] [--service=<service> --operation=<operation>]
```

These commands provide a clear and consistent way to manage permissions:
- `allow` grants permission for a specific path, command, or AWS operation
- `deny` explicitly blocks a specific path, command, or AWS operation (overrides allow rules)
- `remove-rule` removes a rule from either the allow or deny list, resetting to default behavior

This approach provides several advantages:
- Clear intent: Commands clearly communicate the expected outcome
- Explicit precedence: Makes it clear that deny overrides allow
- Unified removal: Single command to remove rules from either list

## Path-Based Permissions

Users can specify allowed and denied paths for filesystem operations:

```
/tools allow fs_read --path=/path/to/project/**
/tools allow fs_write --path=/path/to/output/**
/tools deny fs_write --path=/path/to/project/config/**
```

This allows Amazon Q to:
- Read from `/path/to/project` and all its subdirectories without confirmation
- Write to `/path/to/output` and all its subdirectories without confirmation
- Never write to `/path/to/project/config` or its subdirectories (even if a broader allow rule exists)

Path patterns support glob-style syntax:
- `*` matches any sequence of characters within a path component
- `**` matches zero or more path components
- `?` matches any single character

## Command-Based Permissions

For the `execute_bash` tool, users can allow or deny specific commands using a flat command storage approach:

```
/tools allow execute_bash --command="git status"
/tools allow execute_bash --command="git log"
/tools allow execute_bash --command="ls *"
/tools deny execute_bash --command="rm -rf *"
```

This allows Amazon Q to:
- Run `git status` without confirmation
- Run `git log` without confirmation
- Run any `ls` command without confirmation
- Never run `rm -rf *` (even if broader permissions exist)

Command patterns support glob-style syntax:
- `command *` matches the command with any arguments
- `command arg1 *` matches the command with a specific first argument and any additional arguments

## AWS CLI Permissions

For the `use_aws` tool, users can allow or deny specific service/operation combinations:

```
/tools allow use_aws --service=s3 --operation="get*"
/tools allow use_aws --service="*" --operation="describe*"
/tools deny use_aws --service=iam --operation="*"
```

This allows Amazon Q to:
- Run any S3 get operations without confirmation
- Run any describe operations on any service without confirmation
- Never run any IAM operations

This pattern-based approach is particularly useful for AWS operations, allowing users to:
- Allow all read-only operations (`get*`, `describe*`, `list*`)
- Allow operations on specific services
- Block sensitive services or operations

## Viewing Current Permissions

Users can see their current permission settings with enhanced detail:

```
> /tools
Current tools and permissions:

- fs_read

    Allowed Paths:
      ./*
      /users/me/documents/*

    Denied Paths:
      ./data/secrets.txt


- fs_write

    Allowed Paths:
      <none>

    Denied Paths:
      *


- execute_bash:
    
    Allowed Commands:
      git status
      git log
      ls *
    
    Denied Commands:
      git push
      git commit
      rm -rf *


- use_aws:
    
    Allowed Operations:
      s3 get*
      ec2 describe*
    
    Denied Operations:
      iam *


- report_issue:
    Trusted
```

The UI groups related commands for better readability while maintaining the flat storage model internally.

## Interactive Trust Decision

When Amazon Q attempts to use a tool that requires confirmation, users now have expanded options:

```
Amazon Q: I'll check the contents of your file.
[Tool Request: fs_read (path=/Users/user/config.json)]
Allow this action? [y/n/t/a/d]: _
```

Where:
- `y` = Allow this specific request
- `n` = Deny this specific request
- `t` = Trust this tool for the session (no more prompts for this tool)
- `a` = Allow this specific path/command/operation for the session
- `d` = Deny this specific path/command/operation for the session

This interactive approach makes it easy to create rules at the moment they're needed, without requiring users to remember complex command syntax.

## Rule Precedence

Rules follow a clear precedence order:
1. Deny rules always take precedence over allow rules
2. More specific patterns take precedence over general ones
3. In case of equal specificity, the most recently added rule wins

This ensures that security boundaries are maintained even when broader permissions are granted.

## Backward Compatibility

All existing tool permission commands continue to work as before:

```
/tools trust fs_read       # Still works - trusts all fs_read operations
/acceptall                 # Still works - trusts all tools
/tools untrust execute_bash # Still works - requires confirmation for all execute_bash operations
```

# Reference-level explanation

## Data Structures

We'll extend the existing `ToolPermission` structure to support the allow/deny model:

```rust
/// Represents a pattern-based permission rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRule {
    /// The pattern to match against (path, command, etc.)
    pattern: String,
    /// Whether this rule grants permission when matched
    is_allowed: bool,
}

/// Enhanced tool permission structure
#[derive(Debug, Clone)]
pub struct ToolPermission {
    /// Whether the entire tool is trusted (from RFC-0002)
    trusted: bool,
    /// Rules for filesystem paths
    path_rules: Vec<PermissionRule>,
    /// Rules for shell commands (stored as flat strings)
    command_rules: Vec<PermissionRule>,
    /// Rules for AWS service/operation combinations
    aws_rules: Vec<PermissionRule>,
}

#[derive(Debug, Clone)]
pub struct ToolPermissions {
    permissions: HashMap<String, ToolPermission>,
}
```
## Pattern Matching System

For efficient pattern matching, we'll use glob-style patterns with a specificity hierarchy:

```rust
/// Calculates the specificity of a pattern (higher is more specific)
fn calculate_specificity(pattern: &str) -> u32 {
    let mut specificity = 0;
    
    // Exact characters increase specificity
    specificity += pattern.chars().filter(|c| *c != '*' && *c != '?').count() as u32 * 10;
    
    // Single wildcards (?) are more specific than multi-wildcards (*)
    specificity += pattern.chars().filter(|c| *c == '?').count() as u32 * 5;
    
    // Double wildcards (**) reduce specificity significantly
    specificity -= pattern.matches("**").count() as u32 * 50;
    
    specificity
}

/// Matches a value against a pattern
fn pattern_matches(pattern: &str, value: &str) -> bool {
    // Implementation using the globset crate for efficient pattern matching
    let glob = globset::Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .unwrap_or_else(|_| globset::GlobMatcher::new());
    
    glob.is_match(value)
}
```

## Permission Checking Logic

The permission checking flow will handle the different rule types:

```rust
fn is_path_allowed(&self, tool_name: &str, path: &str) -> bool {
    let permission = match self.permissions.get(tool_name) {
        Some(p) => p,
        None => return false,
    };
    
    // If the entire tool is trusted, allow it
    if permission.trusted {
        return true;
    }
    
    // First check for explicit denials
    for rule in &permission.path_rules {
        if !rule.is_allowed && pattern_matches(&rule.pattern, path) {
            return false; // Denied by explicit rule
        }
    }
    
    // Then check for allows, sorted by specificity
    let mut allow_rules: Vec<&PermissionRule> = permission.path_rules
        .iter()
        .filter(|r| r.is_allowed)
        .collect();
    
    // Sort by specificity (most specific first)
    allow_rules.sort_by(|a, b| {
        let a_spec = calculate_specificity(&a.pattern);
        let b_spec = calculate_specificity(&b.pattern);
        b_spec.cmp(&a_spec).then_with(|| b.created_at.cmp(&a.created_at))
    });
    
    for rule in allow_rules {
        if pattern_matches(&rule.pattern, path) {
            return true;
        }
    }
    
    false
}
```

Similar logic applies for command and AWS operation permissions.
## Command Parsing and Handling

The `/tools` command will be extended to support the new allow/deny/remove-rule syntax:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolsSubcommand {
    // Existing commands from RFC-0002
    Trust { tool_name: String },
    Untrust { tool_name: String },
    TrustAll,
    Reset,
    
    // New commands
    Allow { 
        tool_name: String, 
        path: Option<String>,
        command: Option<String>,
        service: Option<String>,
        operation: Option<String>,
    },
    Deny { 
        tool_name: String, 
        path: Option<String>,
        command: Option<String>,
        service: Option<String>,
        operation: Option<String>,
    },
    RemoveRule { 
        tool_name: String, 
        path: Option<String>,
        command: Option<String>,
        service: Option<String>,
        operation: Option<String>,
    },
    Help,
}

fn handle_tools_command(&mut self, args: &str) -> Result<()> {
    let args = args.trim();
    
    if args.is_empty() {
        self.show_tool_permissions()?;
        return Ok(());
    }
    
    let parts: Vec<&str> = args.split_whitespace().collect();
    match parts[0] {
        "allow" if parts.len() > 1 => {
            let tool_name = parts[1];
            self.handle_allow_command(tool_name, &parts[2..])?;
        },
        "deny" if parts.len() > 1 => {
            let tool_name = parts[1];
            self.handle_deny_command(tool_name, &parts[2..])?;
        },
        "remove-rule" if parts.len() > 1 => {
            let tool_name = parts[1];
            self.handle_remove_rule_command(tool_name, &parts[2..])?;
        },
        // Existing commands...
        _ => {
            self.output_tools_help()?;
        }
    }
    
    Ok(())
}
```

## Interactive Prompt

The interactive prompt will be updated to handle the new options:

```rust
fn prompt_for_tool_execution(&mut self, tool: &Tool) -> Result<ToolPromptResponse> {
    match tool {
        Tool::FsRead(fs_read) => {
            let path = fs_read.path.display().to_string();
            execute!(
                self.output,
                style::SetForegroundColor(Color::Yellow),
                style::Print(format!("[Tool Request: fs_read (path={})]\n", path)),
                style::Print("Allow this action? [y/n/t/a/d]: "),
                style::SetForegroundColor(Color::Reset)
            )?;
            
            // Read user input
            let response = self.read_line()?.to_lowercase();
            match response.as_str() {
                "y" => Ok(ToolPromptResponse::Yes),
                "n" => Ok(ToolPromptResponse::No),
                "t" => Ok(ToolPromptResponse::Trust),
                "a" => Ok(ToolPromptResponse::Allow(path)),
                "d" => Ok(ToolPromptResponse::Deny(path)),
                _ => self.prompt_for_tool_execution(tool), // Reprompt on invalid input
            }
        },
        // Similar implementations for other tool types
        // ...
    }
}
```

## Storage

Permission rules will be stored in memory for the current session only, consistent with the existing tool permissions system. This avoids persistent security risks while providing convenience within a session.

# Drawbacks

1. **Increased Complexity**: The permission system becomes more complex for users to understand and for developers to implement.

2. **Learning Curve**: Users will need to learn the allow/deny/remove-rule model and pattern syntax.

3. **UI Challenges**: Representing complex permission rules in a command-line interface is challenging.

4. **Pattern Matching Edge Cases**: Glob-style pattern matching can have edge cases and security implications.

5. **Performance Impact**: More complex permission checks could impact performance slightly.

# Rationale and alternatives

## Why this design?

This design was chosen because it:

1. **Clear Intent**: The allow/deny/remove-rule model makes the intent of each command explicit
2. **Explicit Precedence**: Establishes a clear precedence (deny overrides allow)
3. **Unified Removal**: Provides a single command to remove rules from either list
4. **Flat Command Storage**: Simplifies implementation while still providing the necessary granularity
5. **Familiar Patterns**: Uses glob-style patterns familiar to developers
6. **Backward Compatibility**: Maintains compatibility with existing commands

## Alternatives considered

### 1. Trust/Untrust with Path/Command Parameters

Instead of allow/deny, we could extend the existing trust/untrust commands:

```
/tools trust fs_read --path=/path/to/project
/tools untrust fs_write --path=/path/to/config
```

**Pros**:
- Builds directly on existing commands
- Fewer new concepts to learn

**Cons**:
- Less clear how trust/untrust interact with both allow and deny lists
- Ambiguity about precedence
- No clear way to remove rules

### 2. Hierarchical Command Structure

Instead of flat command storage, use a hierarchical structure:

```rust
allowed = {
  "git": ["status", "log"],
  "ls": ["-la", "-l"]
}
```

**Pros**:
- More structured representation
- Potentially cleaner UI

**Cons**:
- More complex implementation
- Not all commands fit neatly into a hierarchy
- Inconsistent modeling between different command types

### 3. Regular Expression Patterns

Instead of glob-style patterns, use regular expressions:

**Pros**:
- More expressive pattern matching
- Standard pattern syntax

**Cons**:
- More complex for users to understand
- Security implications of complex regex patterns
- Higher implementation complexity

## Impact of not doing this

Without this feature:
- Users will continue to face the all-or-nothing choice at the tool level
- Security-conscious users will be prompted more frequently than necessary
- Users may avoid using Amazon Q for certain tasks due to prompt fatigue

# Unresolved questions

1. **Pattern Syntax Details**: What specific pattern syntax should we use? Should we adopt an existing library like `globset` or implement our own pattern matching?

2. **Command Parsing Complexity**: How should we parse and match shell commands, especially considering shell quoting and variable expansion?

3. **Rule Precedence Algorithm**: What is the optimal algorithm for determining rule precedence when multiple patterns match?

4. **AWS Service Operation Granularity**: For AWS operations, what's the right level of granularity? Should we allow patterns on service names, operation names, resource ARNs, or combinations of these?

5. **Performance Optimization**: How can we optimize pattern matching to minimize performance impact?

# Future possibilities

1. **Permission Presets**: Allow users to define and switch between permission presets for different workflows.

2. **Time-Limited Permissions**: Allow permissions to expire after a certain time or number of uses.

3. **Permission Auditing**: Provide a log of permission grants and tool uses for review.

4. **Integration with Profiles**: Allow saving trusted paths/commands as part of user profiles.

5. **Visual Permission Manager**: Add a TUI interface for managing complex permissions.

6. **Command Suggestions**: Suggest common commands to trust based on usage patterns.

7. **Risk Assessment**: Provide risk assessments for commands before trusting them.
