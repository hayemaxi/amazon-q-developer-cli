- Feature Name: extra_granular_permissions
- Start Date: 2025-04-14
- RFC PR: [amazon-q-developer-cli#XXX](https://github.com/aws/amazon-q-developer-cli/pull/XXX)

# Summary

[summary]: #summary

This RFC proposes extending the existing granular tool permissions system to provide fine-grained control over tool execution in Amazon Q Developer CLI. It introduces path-based permissions for filesystem operations, command and argument-level permissions for the `execute_bash` tool, and a pattern-matching system that allows users to trust specific operation patterns without requiring confirmation for every similar action. This enhancement significantly improves user experience by reducing unnecessary prompts while maintaining strong security boundaries for sensitive operations.

# Motivation

[motivation]: #motivation

While the current granular tool permissions system (RFC-0002) allows users to trust specific tools for the entire session, it still operates at a coarse level. Users must either trust a tool completely or approve each individual use. This creates friction in common workflows where users might want to:

1. Trust filesystem operations only within specific project directories while protecting sensitive areas
2. Allow certain shell commands but not others (e.g., allow `git status` but require confirmation for `git push`)
3. Trust specific command patterns with certain arguments (e.g., `aws s3 ls` but not other AWS commands)
4. Reduce interruptions for repetitive but safe operations while maintaining protection for destructive ones

In user testing and feedback, we've observed that:

- Users frequently approve the same operations repeatedly, leading to "prompt fatigue"
- Some users resort to trusting entire tools when they only need a subset of functionality
- Development workflows are interrupted by unnecessary security prompts for safe operations
- Users working on multiple projects want different permission levels for different directories

By providing more granular control, we can improve user experience by reducing unnecessary prompts while maintaining security for sensitive operations. This approach aligns with the principle of least privilege, allowing users to grant only the specific permissions needed for their workflow.

# Guide-level explanation

[guide-level-explanation]: #guide-level-explanation

## Overview

The extra granular permissions system builds upon the existing tool permissions framework by adding pattern-based rules that can be applied to specific tools. These rules define conditions under which a tool can execute without requiring explicit user confirmation.

## Key Concepts

### Path-Based Permissions

Users can specify trusted paths for filesystem operations using glob patterns:

```
/tools trust fs_read --path=/Volumes/workplace/myproject/**
/tools trust fs_write --path=/Volumes/workplace/myproject/output/**
/tools trust fs_read --path=/home/user/docs/*.md
```

This allows Amazon Q to:
- Read any files within the `myproject` directory and its subdirectories
- Write only to the `output` subdirectory without prompting
- Read Markdown files in the user's docs directory

Path patterns support standard glob syntax:
- `*` matches any sequence of characters within a path component
- `**` matches zero or more path components (directories)
- `?` matches any single character

### Command-Based Permissions for Shell Execution

For the `execute_bash` tool, users can specify trusted commands or command patterns:

```
/tools trust execute_bash --command="git status"
/tools trust execute_bash --command="ls **"
/tools trust execute_bash --command="aws s3 ls s3://my-bucket/**"
```

This allows Amazon Q to run specific commands without confirmation:
- The exact `git status` command
- Any `ls` command with any arguments
- AWS S3 list operations, but only for a specific bucket

Command patterns can be as specific or broad as needed:
- Exact command matching: `git status`
- Command with any arguments: `git status **`
- Command with specific first argument: `git pull origin *`

### AWS CLI Specific Controls

For the `use_aws` tool, users can specify trusted service and operation combinations:

```
/tools trust use_aws --service=s3api --operation=list-objects
/tools trust use_aws --service=ec2 --operation=describe-*
```

This allows fine-grained control over AWS operations:
- Allow listing S3 objects without confirmation
- Allow all EC2 describe operations but prompt for modifications

### Permission Rules Management

Users can view, list, and manage their permission rules:

```
> /tools rules
Current permission rules:
- fs_read: /Volumes/workplace/myproject/** (Trusted)
- fs_write: /Volumes/workplace/myproject/output/** (Trusted)
- execute_bash: git status (Trusted)
- execute_bash: ls ** (Trusted)
- use_aws: s3api/list-objects (Trusted)

> /tools rules remove fs_write --path=/Volumes/workplace/myproject/output/**
Rule removed.
```

### Interactive Rule Creation

When prompted for tool approval, users can now create rules directly:

```
Amazon Q: I'll check the status of your git repository.
[Tool Request: execute_bash (command=git status)]
Allow this action? [y/n/t/r]: r

Create rule for: git status
1. Trust this exact command only
2. Trust all 'git status' commands with any arguments
3. Trust all 'git' commands
> 2

Rule added: execute_bash --command="git status **"
Executing command...
```

Where:
- `y` = Allow this specific request
- `n` = Deny this specific request
- `t` = Trust this tool for the session (no more prompts for this tool)
- `r` = Create a custom rule for this tool

### Negative Rules (Blocklist)

Users can also create negative rules to explicitly block certain patterns:

```
/tools block fs_write --path=/Volumes/workplace/myproject/config/**
/tools block execute_bash --command="rm -rf *"
```

This ensures that even if broader permissions are granted, sensitive operations remain protected.

### Rule Precedence

Rules follow a clear precedence order:
1. Explicit blocks always take precedence
2. More specific patterns take precedence over general ones
3. In case of equal specificity, the most recently added rule wins

### Backward Compatibility

All existing tool permission commands continue to work as before. The new functionality is additive and builds upon the existing system:

```
/tools trust fs_read       # Still works - trusts all fs_read operations
/acceptall                 # Still works - trusts all tools
/tools untrust execute_bash # Still works - requires confirmation for all execute_bash operations
```

# Reference-level explanation

[reference-level-explanation]: #reference-level-explanation

## Data Structures

We'll extend the existing `ToolPermission` structure to support pattern-based rules:

```rust
/// Represents a pattern-based permission rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRule {
    /// The pattern to match against (path, command, etc.)
    pattern: String,
    /// Whether this rule grants permission when matched
    is_allowed: bool,
    /// When this rule was created (for precedence resolution)
    created_at: DateTime<Utc>,
    /// Optional description for the rule
    description: Option<String>,
}

/// Enhanced tool permission structure
#[derive(Debug, Clone)]
pub struct ToolPermission {
    /// Whether the entire tool is trusted (from RFC-0002)
    trusted: bool,
    /// Path-based rules for filesystem tools
    path_rules: Vec<PermissionRule>,
    /// Command-based rules for execute_bash
    command_rules: Vec<PermissionRule>,
    /// Service/operation rules for use_aws
    aws_rules: Vec<PermissionRule>,
}

#[derive(Debug, Clone)]
pub struct ToolPermissions {
    permissions: HashMap<String, ToolPermission>,
}

/// Enum representing different rule types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Path,
    Command,
    AwsOperation,
}

/// Struct for rule creation suggestions
#[derive(Debug, Clone)]
pub struct RuleSuggestion {
    rule_type: RuleType,
    pattern: String,
    description: String,
}
```

## Pattern Matching System

The pattern matching system will use glob-style patterns with a clear hierarchy of specificity:

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
```

For path patterns:
- `*` matches any sequence of characters within a path component
- `**` matches zero or more path components
- `?` matches any single character

For command patterns:
- Command patterns are split into the command name and arguments
- `command **` would match any invocation of that command regardless of arguments
- `command arg1 *` would match the command with arg1 and any single additional argument

## Permission Checking Logic

The permission checking flow will be enhanced to handle the new rule types:

```rust
fn is_tool_allowed(&self, tool_name: &str, params: &Value) -> bool {
    let permission = match self.permissions.get(tool_name) {
        Some(p) => p,
        None => return false, // No permission entry means not trusted
    };
    
    // If the entire tool is trusted, allow it
    if permission.trusted {
        return true;
    }
    
    // Check specific rules based on tool type
    match tool_name {
        "fs_read" | "fs_write" => {
            let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
            self.check_path_permission(permission, path)
        },
        "execute_bash" => {
            let command = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
            self.check_command_permission(permission, command)
        },
        "use_aws" => {
            let service = params.get("service_name").and_then(|v| v.as_str()).unwrap_or("");
            let operation = params.get("operation_name").and_then(|v| v.as_str()).unwrap_or("");
            self.check_aws_permission(permission, service, operation)
        },
        _ => false,
    }
}

fn check_path_permission(&self, permission: &ToolPermission, path: &str) -> bool {
    // First check for explicit blocks
    for rule in &permission.path_rules {
        if !rule.is_allowed && self.pattern_matches(&rule.pattern, path) {
            return false; // Blocked by explicit rule
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
        if self.pattern_matches(&rule.pattern, path) {
            return true;
        }
    }
    
    false
}

fn check_command_permission(&self, permission: &ToolPermission, command: &str) -> bool {
    // Similar implementation to check_path_permission but for commands
    // ...
}

fn check_aws_permission(&self, permission: &ToolPermission, service: &str, operation: &str) -> bool {
    // Check AWS service/operation permissions
    // ...
}

fn pattern_matches(&self, pattern: &str, value: &str) -> bool {
    // Implementation using the globset crate for efficient pattern matching
    let glob = globset::Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .unwrap_or_else(|_| globset::GlobMatcher::new());
    
    glob.is_match(value)
}
```

## Command Parsing and Handling

The `/tools` command will be extended to support the new rule-based syntax:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolsSubcommand {
    Trust { tool_name: String },
    Untrust { tool_name: String },
    TrustAll,
    Reset,
    Rules,
    RulesAdd { tool_name: String, rule_type: RuleType, pattern: String },
    RulesRemove { tool_name: String, rule_type: RuleType, pattern: String },
    Block { tool_name: String, rule_type: RuleType, pattern: String },
    Unblock { tool_name: String, rule_type: RuleType, pattern: String },
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
        // Existing commands from RFC-0002
        "trust" if parts.len() > 1 => {
            // Check for new pattern-based syntax
            if parts.len() > 2 && parts[2].starts_with("--") {
                self.handle_pattern_trust(parts[1], &parts[2..])?;
            } else {
                self.tool_permissions.trust_tool(parts[1]);
                self.output_tool_now_trusted(parts[1])?;
            }
        },
        "rules" if parts.len() == 1 => {
            self.show_permission_rules()?;
        },
        "rules" if parts.len() > 1 && parts[1] == "add" => {
            self.handle_rules_add(&parts[2..])?;
        },
        "rules" if parts.len() > 1 && parts[1] == "remove" => {
            self.handle_rules_remove(&parts[2..])?;
        },
        "block" if parts.len() > 1 => {
            self.handle_block(parts[1], &parts[2..])?;
        },
        // Other commands...
        _ => {
            self.output_tools_help()?;
        }
    }
    
    Ok(())
}

fn handle_pattern_trust(&mut self, tool_name: &str, args: &[&str]) -> Result<()> {
    // Parse arguments like --path=/some/path or --command="git status"
    let mut path = None;
    let mut command = None;
    let mut service = None;
    let mut operation = None;
    
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--path" => {
                if i + 1 < args.len() {
                    path = Some(args[i + 1]);
                    i += 2;
                } else {
                    return Err(eyre::eyre!("Missing value for --path"));
                }
            },
            arg if arg.starts_with("--path=") => {
                path = Some(&arg[7..]);
                i += 1;
            },
            "--command" => {
                if i + 1 < args.len() {
                    command = Some(args[i + 1]);
                    i += 2;
                } else {
                    return Err(eyre::eyre!("Missing value for --command"));
                }
            },
            arg if arg.starts_with("--command=") => {
                command = Some(&arg[10..]);
                i += 1;
            },
            // Handle other arguments...
            _ => {
                i += 1;
            }
        }
    }
    
    // Add the appropriate rule based on the tool and arguments
    match tool_name {
        "fs_read" | "fs_write" => {
            if let Some(p) = path {
                self.tool_permissions.add_path_rule(tool_name, p, true)?;
                self.output_path_rule_added(tool_name, p)?;
            } else {
                return Err(eyre::eyre!("Missing --path for filesystem tool"));
            }
        },
        "execute_bash" => {
            if let Some(cmd) = command {
                self.tool_permissions.add_command_rule(tool_name, cmd, true)?;
                self.output_command_rule_added(tool_name, cmd)?;
            } else {
                return Err(eyre::eyre!("Missing --command for execute_bash"));
            }
        },
        // Handle other tools...
        _ => {
            return Err(eyre::eyre!("Unsupported tool for pattern-based permissions"));
        }
    }
    
    Ok(())
}
```

## Interactive Rule Creation

When a user chooses to create a rule during tool approval, we'll present appropriate options based on the tool type:

```rust
fn handle_rule_creation(&mut self, tool_name: &str, params: &Value) -> Result<()> {
    match tool_name {
        "fs_read" | "fs_write" => {
            self.handle_filesystem_rule_creation(tool_name, params)?;
        },
        "execute_bash" => {
            self.handle_command_rule_creation(tool_name, params)?;
        },
        "use_aws" => {
            self.handle_aws_rule_creation(tool_name, params)?;
        },
        _ => {
            execute!(
                self.output,
                style::SetForegroundColor(Color::Yellow),
                style::Print("Rule creation not supported for this tool type.\n"),
                style::SetForegroundColor(Color::Reset)
            )?;
        }
    }
    
    Ok(())
}

fn handle_command_rule_creation(&mut self, tool_name: &str, params: &Value) -> Result<()> {
    let command = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
    
    // Generate rule suggestions based on the command
    let suggestions = self.generate_command_rule_suggestions(command);
    
    execute!(
        self.output,
        style::SetForegroundColor(Color::Cyan),
        style::Print(format!("\nCreate rule for: {}\n", command)),
        style::SetForegroundColor(Color::Reset)
    )?;
    
    // Display numbered suggestions
    for (i, suggestion) in suggestions.iter().enumerate() {
        execute!(
            self.output,
            style::Print(format!("{}. {}\n", i + 1, suggestion.description))
        )?;
    }
    
    execute!(self.output, style::Print("> "))?;
    let choice = self.read_line()?;
    
    // Parse choice and add the selected rule
    if let Ok(index) = choice.trim().parse::<usize>() {
        if index > 0 && index <= suggestions.len() {
            let selected = &suggestions[index - 1];
            self.tool_permissions.add_command_rule(tool_name, &selected.pattern, true)?;
            
            execute!(
                self.output,
                style::SetForegroundColor(Color::Green),
                style::Print(format!("\nRule added: {} --command=\"{}\"\n", tool_name, selected.pattern)),
                style::SetForegroundColor(Color::Reset)
            )?;
        }
    }
    
    Ok(())
}

fn generate_command_rule_suggestions(&self, command: &str) -> Vec<RuleSuggestion> {
    let mut suggestions = Vec::new();
    
    // Split command into parts
    let parts: Vec<&str> = command.split_whitespace().collect();
    
    if !parts.is_empty() {
        // Exact command
        suggestions.push(RuleSuggestion {
            rule_type: RuleType::Command,
            pattern: command.to_string(),
            description: format!("Trust this exact command only"),
        });
        
        // Command with any arguments
        suggestions.push(RuleSuggestion {
            rule_type: RuleType::Command,
            pattern: format!("{} **", parts[0]),
            description: format!("Trust all '{}' commands with any arguments", parts[0]),
        });
        
        // If there are subcommands (like git status, aws s3 ls)
        if parts.len() > 1 {
            suggestions.push(RuleSuggestion {
                rule_type: RuleType::Command,
                pattern: format!("{} {} **", parts[0], parts[1]),
                description: format!("Trust all '{} {}' commands with any arguments", parts[0], parts[1]),
            });
        }
    }
    
    suggestions
}
```

## Storage

Permission rules will be stored in memory for the current session only, consistent with the existing tool permissions system. This avoids persistent security risks while providing convenience within a session.

## Security Considerations

The implementation includes several security measures:

1. **Explicit Blocks**: Block rules always take precedence over allow rules
2. **Specificity Ordering**: More specific patterns take precedence over general ones
3. **Default Deny**: Any operation not explicitly allowed is denied
4. **Session-Only Storage**: Rules are not persisted across sessions
5. **Clear Feedback**: Users receive clear feedback about which rules are being applied

## Performance Considerations

To ensure efficient pattern matching, especially with potentially many rules:

1. We'll use the `globset` crate for optimized glob pattern matching
2. Rules will be sorted by specificity to check more specific rules first
3. Block rules will be checked before allow rules to fail fast
4. Pattern compilation will be cached where possible

# Drawbacks

[drawbacks]: #drawbacks

1. **Increased Complexity**: Adding pattern-based permissions significantly increases the complexity of the permission system, both in terms of implementation and user understanding. The additional options and syntax may be overwhelming for some users.

2. **Learning Curve**: Users will need to learn pattern syntax and understand how different patterns apply to different tools. The glob pattern syntax, while familiar to many developers, may be confusing to less technical users.

3. **UI Complexity**: The command-line interface becomes more complex with additional options and parameters. This could make the tool less approachable for new users.

4. **Performance Impact**: Pattern matching, especially for complex patterns and large numbers of rules, could introduce performance overhead when checking permissions. Each tool use would require evaluating multiple patterns.

5. **Security Risks**: More granular permissions could lead to unintended security holes if users create overly broad patterns without fully understanding their implications. For example, a user might accidentally trust a pattern that includes sensitive directories.

6. **Maintenance Burden**: The increased complexity will require more testing and maintenance effort, especially as new tools are added to the system. Each new tool may require specialized pattern handling.

7. **Cognitive Load**: Users may struggle to remember which patterns they've trusted, leading to confusion about why certain operations require confirmation while others don't.

8. **Implementation Challenges**: Correctly implementing pattern matching for different tool types, especially for shell commands with complex quoting and argument handling, presents significant technical challenges.

# Rationale and alternatives

[rationale-and-alternatives]: #rationale-and-alternatives

## Why this design?

This design was chosen because it:

1. **Builds on existing foundations**: It extends the existing tool permissions system rather than replacing it, maintaining backward compatibility and leveraging users' existing knowledge.

2. **Addresses real user needs**: It solves common friction points where users want to trust specific operations but not entire tools. This is based on actual user feedback and observed usage patterns.

3. **Uses familiar patterns**: The glob-style pattern matching is familiar to developers from file systems, shell commands, and gitignore files. This reduces the learning curve by building on existing knowledge.

4. **Balances security and convenience**: It maintains the security principle of explicit permission while reducing unnecessary interruptions. Users can grant precisely the permissions needed for their workflow.

5. **Provides flexibility**: The pattern-based approach can be extended to new tools and use cases without changing the core permission model. This ensures the system can evolve as new tools are added.

6. **Follows principle of least privilege**: Users can grant the minimum permissions necessary for their workflow, rather than trusting entire tools.

7. **Supports interactive creation**: The interactive rule creation flow makes it easy for users to create appropriate rules without needing to understand the full syntax.

## Alternatives considered

### 1. Directory Allowlists

Instead of pattern matching, we could implement a simpler directory allowlist system where users specify directories that are trusted for specific operations.

**Pros**:
- Simpler to understand and implement
- Less potential for security issues from complex patterns
- More explicit about which directories are trusted

**Cons**:
- Less flexible than pattern matching
- Doesn't address command-level permissions for `execute_bash`
- Would require a separate permission model for each tool type
- Doesn't handle nested directory structures elegantly

This was rejected because it lacks the flexibility needed to address the full range of use cases, particularly for command-based tools.

### 2. Permission Presets

We could define common permission presets (e.g., "development mode", "read-only mode") that users could switch between.

**Pros**:
- Simple for users to understand and use
- Provides a curated set of permissions for common workflows
- Reduces the need for users to create their own rules

**Cons**:
- Presets would be too generic for many workflows
- Users would still need a way to customize permissions for their specific needs
- It would be difficult to define presets that work well across different environments
- Less flexibility for specialized workflows

This was rejected because it wouldn't provide the fine-grained control that users need for their specific workflows.

### 3. Persistent Permissions

We could store permission rules in user profiles, making them persistent across sessions.

**Pros**:
- Users wouldn't need to recreate rules for each session
- Better for long-running projects
- Could support sharing rules between team members

**Cons**:
- Introduces long-term security risks if users forget which patterns they've trusted
- Session-based permissions provide a good balance between convenience and security
- Would require additional storage and management code
- Could lead to confusion about which rules are active

This was rejected for security reasons, but could be considered as a future enhancement with appropriate safeguards.

### 4. Tool-Specific Configuration Files

We could use tool-specific configuration files (similar to `.gitignore`) to define trusted patterns.

**Pros**:
- Familiar format for many developers
- Could be checked into version control for team sharing
- Separates configuration from command-line interface

**Cons**:
- Adds complexity of managing configuration files
- Less interactive than command-line options
- Harder to make quick adjustments during a session

This was rejected because it adds complexity and reduces the interactive nature of the tool.

### 5. Do Nothing

We could keep the current tool-level permissions without adding pattern-based rules.

**Pros**:
- Maintains simplicity of the current system
- No additional implementation or maintenance burden
- No new concepts for users to learn

**Cons**:
- Users would continue to face interruptions for repetitive but safe operations
- The user experience would remain suboptimal for common development workflows
- Users might be tempted to trust entire tools when they only need to trust specific operations
- Doesn't address the specific user needs identified in the motivation section

This was rejected because it fails to address the user experience issues identified in the motivation section.

# Unresolved questions

[unresolved-questions]: #unresolved-questions

1. **Pattern Syntax Details**: What specific pattern syntax should we use? Should we adopt an existing library like `globset` or implement our own pattern matching? How should we handle edge cases like case sensitivity and special characters?

2. **Command Parsing Complexity**: How should we parse and match shell commands, especially considering shell quoting, variable expansion, and the wide variety of command structures? Should we attempt to understand command semantics or treat them as opaque strings?

3. **Rule Precedence Algorithm**: What is the optimal algorithm for determining rule precedence when multiple patterns match? How do we balance specificity, recency, and explicit allow/deny rules?

4. **Rule Management Interface**: What's the most user-friendly way to allow users to manage (list, edit, delete) existing rules? Should we provide a dedicated TUI interface for complex rule management?

5. **Performance Optimization Strategies**: How can we optimize pattern matching to minimize performance impact, especially for large numbers of rules? Should we implement caching, pre-compilation of patterns, or other optimizations?

6. **User Experience Refinement**: What's the best way to present pattern-based permissions in the UI to make them understandable to users? How do we provide enough feedback without overwhelming users?

7. **Tool-Specific Parameter Handling**: Should different tools have different parameter types for pattern matching (e.g., `--path` for filesystem tools, `--command` for execute_bash)? How do we maintain consistency while addressing tool-specific needs?

8. **AWS Service Operation Granularity**: For AWS operations, what's the right level of granularity? Should we allow patterns on service names, operation names, resource ARNs, or combinations of these?

9. **Negative Rule Implementation**: How should negative rules (blocks) be implemented and presented to users? Should they be a separate concept or just rules with `is_allowed=false`?

10. **Rule Suggestion Algorithm**: What algorithm should we use to generate rule suggestions during interactive rule creation? How do we balance specificity and usability?

11. **Testing Strategy**: What's the best approach to comprehensively test the pattern matching system across different tools and pattern types?

## Example Permission Schema

To better illustrate how the granular permission system could be conceptually structured, here's an example schema that represents the different types of permissions and their relationships:

```json
{
  "tool_permissions": {
    "fs_read": {
      "allowed_paths": [
        "/Volumes/workplace/myproject/**/*.{js,ts,json}",
        "/home/user/docs/*.md",
        "/tmp/workspace/"
      ],
      "denied_paths": [
        "**/node_modules/**",
        "**/secrets/**",
        "**/credentials.*"
      ],
      "max_file_size": 10485760,  // 10MB limit
      "allow_hidden_files": false
    },
    "fs_write": {
      "allowed_paths": [
        "/Volumes/workplace/myproject/output/**",
        "/tmp/workspace/generated/"
      ],
      "denied_paths": [
        "**/config/**",
        "**/*.{sh,exe,bin}",
        "**/package.json"
      ],
      "max_file_size": 1048576,  // 1MB limit
      "backup_files": true,
      "require_confirmation_for": ["**/src/**/*.{js,ts}"]
    },
    "execute_bash": {
      "allowed_commands": {
        "git": {
          "allowed_subcommands": ["status", "log", "diff", "branch"],
          "denied_subcommands": ["push", "commit"],
          "allowed_args": {
            "status": ["--short", "-s", "--branch", "-b"],
            "log": ["--oneline", "--graph", "--max-count=*"]
          }
        },
        "ls": {
          "allowed_args": ["-l", "-a", "--color", "-h"],
          "allowed_paths": ["**/src", "**/docs"]
        },
        "find": {
          "allowed_args": ["-name", "-type"],
          "allowed_paths": ["/Volumes/workplace/myproject"],
          "denied_args": ["-delete", "-exec"]
        }
      },
      "denied_commands": ["rm", "mv", "cp", "chmod", "chown", "sudo", "curl"],
      "max_runtime": 60  // 60 seconds
    },
    "use_aws": {
      "allowed_services": {
        "s3api": {
          "allowed_operations": ["list-objects", "get-object", "head-object"],
          "denied_operations": ["delete-*", "put-*"],
          "resource_restrictions": {
            "bucket": ["my-allowed-bucket", "test-bucket-*"],
            "prefix": ["public/", "data/readonly/"]
          }
        },
        "ec2": {
          "allowed_operations": ["describe-*"],
          "denied_operations": ["*"]  // Only allow describe operations
        }
      },
      "denied_services": ["iam", "organizations", "kms", "secretsmanager"]
    }
  },
  "global_settings": {
    "default_action": "deny",  // Deny by default if no rule matches
    "rule_precedence": ["denied", "allowed"],  // Denied rules take precedence
    "notification_level": "verbose"  // Show detailed permission notifications
  }
}
```

This schema demonstrates how different tools can have specialized permission structures that address their unique security considerations:

1. For filesystem operations, permissions are based on path patterns with explicit allow and deny lists
2. For shell commands, permissions can control not just which commands are allowed, but also their arguments and subcommands
3. For AWS operations, permissions can be defined at the service, operation, and resource levels

While the actual implementation would use Rust data structures rather than JSON, this conceptual model illustrates the level of granularity that the permission system aims to provide.

# Future possibilities

[future-possibilities]: #future-possibilities

## Enhanced Permission Management

1. **Persistent Rule Storage**: Allow users to save trusted patterns across sessions, perhaps with an expiration mechanism for security. This could include:
   - Time-limited rules that automatically expire after a set period
   - Usage-limited rules that expire after being used a certain number of times
   - Rules that require periodic re-confirmation

2. **Rule Templates**: Provide pre-defined rule templates for common development workflows:
   - Language-specific templates (Python, JavaScript, Java, etc.)
   - Framework-specific templates (React, Django, Spring, etc.)
   - AWS service-specific templates (S3, EC2, Lambda, etc.)
   - Common development tasks (git operations, testing, deployment)

3. **Visual Rule Builder**: Create a visual interface for building and testing permission patterns:
   - Interactive pattern builder with syntax highlighting
   - Pattern testing against sample paths or commands
   - Visual representation of which files/commands would match a pattern
   - Conflict detection between rules

## Security Enhancements

4. **Security Analysis**: Provide tools to analyze rule sets for potential security issues:
   - Detection of overly broad patterns
   - Identification of rules that grant access to sensitive directories
   - Warnings for potentially dangerous command patterns
   - Suggestions for more secure alternatives

5. **Integration with Other Security Features**: Integrate with other security features:
   - Code signing verification for executed scripts
   - Integrity checking for modified files
   - Integration with AWS IAM permissions
   - Sandboxing for high-risk operations

6. **Permission Auditing**: Add comprehensive logging and auditing of permission decisions:
   - Detailed logs of which rules matched which operations
   - Statistics on rule usage and effectiveness
   - Visualization of permission activity over time
   - Anomaly detection for unusual permission patterns

## Usability Improvements

7. **Contextual Rules**: Make rules that only apply in certain contexts:
   - Directory-specific rules that only apply when in that directory
   - Project-specific rules based on detected project type
   - Rules that apply only during certain operations (e.g., testing, deployment)
   - Time-based rules (e.g., different permissions during work hours)

8. **Rule Sharing**: Allow teams to share permission rule sets:
   - Export/import of rule sets
   - Version control integration for rule sets
   - Team-wide rule templates
   - Role-based rule sets (developer, admin, etc.)

9. **Smart Rule Suggestions**: Use machine learning to suggest rules based on usage patterns:
   - Learning from user approval patterns
   - Suggesting rules based on project structure
   - Identifying common patterns across users
   - Recommending rule optimizations

## Technical Enhancements

10. **Advanced Pattern Matching**: Implement more sophisticated pattern matching:
    - Regular expression support for complex patterns
    - Semantic understanding of commands (e.g., recognizing read vs. write operations)
    - Content-aware permissions (e.g., allow modifications to certain file types)
    - Context-aware permissions based on file content or command output

11. **Tool-Specific Rule Extensions**: Develop specialized rule types for new tools:
    - Database operation permissions
    - Network request permissions
    - Cloud resource permissions beyond AWS
    - Container and virtualization permissions

12. **Performance Optimizations**: Implement advanced performance optimizations:
    - Pattern compilation and caching
    - Decision tree optimization for rule evaluation
    - Parallel pattern matching for large rule sets
    - Adaptive rule ordering based on usage frequency

13. **Integration with IDE and Development Tools**: Extend the permission system to integrate with development environments:
    - IDE plugins for rule management
    - Integration with CI/CD pipelines
    - Terminal integration for improved UX
    - Visual Studio Code extension for rule management
