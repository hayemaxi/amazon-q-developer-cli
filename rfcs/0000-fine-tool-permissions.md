- Feature Name: extra_granular_permissions
- Start Date: 2025-04-14

# Summary

[summary]: #summary

This RFC proposes extending the existing granular tool permissions system (proposed in https://github.com/aws/amazon-q-developer-cli/pull/921) to provide fine-grained control over tool execution. It introduces:
1. path-based permissions for filesystem operations,
2. command and argument-level permissions for the `execute_bash` and `use_aws` tools, and 
3. a pattern-matching system that allows users to trust specific operation patterns without requiring confirmation for every similar action.

# Motivation

[motivation]: #motivation

With the current system, users must either trust a tool completely or approve each individual use. This creates friction in common workflows where users might want to:

1. Trust filesystem operations only within specific project directories
2. Trust certain shell commands but not others (e.g., allow `git status` but require confirmation for `git push`)
3. Trust specific command patterns with certain arguments (e.g., `aws s3 ls` but not other AWS commands)

In user testing and feedback, we've observed that:

- Users frequently approve the same operations repeatedly, leading to "prompt fatigue"
- Some users resort to trusting entire tools when they only need a subset of functionality
- Users working on multiple projects want different permission levels for different directories

# Guide-level explanation

[guide-level-explanation]: #guide-level-explanation

## Core Permission Model

In addition to the current `/tools` command suite, the new permission model introduces three primary commands:

```
/tools allow <tool> [options]
/tools block <tool> [options]
/tools remove-rule <tool> [options]

options:
--path <path>                                # allow or block a path
--command <command>                          # allow or dblockeny a shell command
--service <service> --operation <operation>  # allow or block an aws service
```

These commands provide a clear and consistent way to manage permissions by adding the concept of "rules", i.e. allow rules and block rules:
- `allow` grants permission for a specific path, command, or AWS service operation
    - The specific path/command/operation (or pattern) must match an allowed rule.
- `block` explicitly blocks a specific path, command, or AWS operation (overrides allow rules).
    - This is not required to ensure that Amazon Q prompts for a tool. Rather, it allows the user to configure situations such as "allow all git commands ... except git push"
- `remove-rule` removes a rule from either the allow or block list, resetting to default behavior for that path/command/operation

Tools can be completely trusted using `/tools trust`, which would be the equivalent of allowing all paths/commands (\*). Tools can also be completely untrusted using `/tools untrust`, which would be the equivalent of blocking all paths/commands (\*).

Note: Not all options apply to each tool. To make it clear to the user what sort of permissions they are granting, explicit and tool-specific options are necessary. However, this does not mean that they have a significant amount differing special case logic under the hood. This is explained in the Reference Guide section.


## Path-Based Permissions

Users can specify allowed and blocked paths for filesystem operations:

```
/tools allow fs_read --path /path/to/project/** /path/to/project2/**
Trusted 2 paths for 'fs_write'. I will **not** ask for confirmation before running this tool with these paths.

/tools allow fs_write --path /path/to/output/**
Trusted 1 path for 'fs_read'. I will **not** ask for confirmation before running this tool with that path.

/tools block fs_write --path /path/to/project/config/**
Blocked 1 path for 'fs_write'. I **will** ask for confirmation before running this tool with that path.
```

This allows Amazon Q to:
- Read from `/path/to/project` and `/path/to/project2` and all their subdirectories without confirmation
- Write to `/path/to/output` and all its subdirectories without confirmation
- Prompt to write to `/path/to/project/config` or its subdirectories (despite the broader allow rule existing)

Path patterns support will support standard glob style syntax.


## Command-Based Permissions

For the `execute_bash` tool, users can allow or block specific commands:

```
/tools allow execute_bash --command "git status" "git pull * main"
Trusted 2 commands for 'execute_bash'. I will **not** ask for confirmation before running these commands.

/tools allow execute_bash --command "ls *"
Trusted 1 command for 'execute_bash'. I will **not** ask for confirmation before running this command.

/tools block execute_bash --command "rm -rf *"
Blocked 1 command for 'execute_bash'. I **will** ask for confirmation before running this command.
```

This allows Amazon Q to:
- Run exactly `git status` without confirmation
- Run `git pull <any> main` command without confirmation (pull mainline from any upstream)
- Run any `ls` command without confirmation
- Prompt to run with any args `rm -rf` (even if broader permissions exist)

Command patterns support glob-style syntax:
- `command` matches the complete command with any explicit arguments or options
- `command *` matches the command with any arguments or options
- `command arg1 *` matches the command with a specific first argument and any additional arguments or options
- `command * arg1` matches the command with any arguments as long as the last argument is arg1


## AWS CLI Permissions

For the `use_aws` tool, users can allow or block specific service/operation combinations:

```
/tools allow use_aws --service=s3 --operation="get*"
Trusted 1 command for 'use_aws'. I will **not** ask for confirmation before running this command.

/tools allow use_aws --service="*" --operation="describe*"
Trusted 1 command for 'use_aws'. I will **not** ask for confirmation before running this command.

/tools block use_aws --service=iam --operation="*"
Blocked 1 command for 'use_aws'. I **will** ask for confirmation before running this command.
```

This allows Amazon Q to:
- Run any S3 `get` operations without confirmation
- Run any `describe` operations on any service without confirmation
- Prompt to run any IAM operations

This pattern-based approach is particularly useful for AWS operations, allowing users to:
- Allow all read-only operations (`get*`, `describe*`, `list*`)
- Allow operations on specific services
- Block sensitive services or operations


## Other tools

### Built-In tools

Other tools that do not require further granularity such as `report_issue` continue to work with `/tools trust` and `/tools untrust`, and does not accept any other granular permission commands, e.g.
```
/tools allow report_isuse --path /some/path/*

Error: 'report_issue' does not use path permissions. Use `/tools [trust/untrust] report_issue` to enabled/disable acceptance prompting.
```

### Custom tools from MCP

MCP tools are considered a black box and are given blanket trust/untrust permissions only. Their permissions can only be controlled with the current implementation of `/tools trust` and `/tools untrust`. By default, these tools are marked as `Trusted`


## Viewing Current Permissions

Users can see which tools are trusted (never prompt), untrusted (always prompt), or which tools have granular permission rules. This view displays the default permissions for tools if they are not changed. Tools from MCP are also listed here, however they are marked as `Trusted`/`Untrusted` only.

```
> /tools

Current tools and permissions:
  fs_read
    Trusted Paths
      ./*
      /users/me/documents/*

    Requires confirmation
      ./data/secrets.txt


  fs_write
    Trusted Paths
      <none>

    Requires confirmation
      *


  execute_bash
    Trusted Commands
      git status
      git push

    Requires confirmation
      git push -f


  use_aws
    Trusted Services          Operations
      * (all)                  get*
      s3.                      put*

    Requires confirmation
      iam                      * (all)

  report_issue
    Trusted

  MCP Tools:
    - parse_markdown: Trusted
    - talk_to_other_ai: Per-request
```

To view permissions for a particular tool, the user can run:
```
/tools fs-write

Current permissions for `fs_write`:
  Trusted Paths
    <none>

  Requires confirmation
    *
```

Or to view permissions for tools from MCP, the user can run:
```
/tools --mcp

Current tools and permissions from MCP:
  - parse_markdown: Trusted
  - talk_to_other_ai: Per-request
```


## Rule Removal

Users can run the existing `/tools reset <optional tool name>` command to reset tools to their default permission levels. Alternatively, the `remove-rule` command to remove to remove patterns from the rules.

```
> /tools fs-write

Current permissions for `fs_write`:
  Trusted Paths
    /my/path/

  Requires confirmation
    /my/path/

> /tools remove-rule fs_write --path /my/path/

Rule removed.

> /tools fs-write

Current permissions for `fs_write`:
  Trusted Paths
    <none>

  Requires confirmation
    * (all)
```

### Interactive Rule Creation

When prompted for tool approval, users can now create rules directly:

```
Amazon Q: I'll check the status of your git repository.
[Tool Request: execute_bash (command=git status)]
... tool details ...
Allow this action? Use 'c' to configure tool permission. [y/n/c]:

> c

Create rule for: execute_bash (command=git status)
Trusted commands do not ask for confirmation before running.

1. Trust this exact command only
2. Trust all 'git status' commands with any arguments
3. Trust all 'git' commands
4. Trust all requests from this tool 'execute_bash'
Or, 'y' to run without adding a rule:

> 2

Rule added: execute_bash --command="git status *"

Executing command...
```

For MCP tools, the prompt would be what is currently available.
```
[Tool Request: parse_markdown]
... tool details ...
Allow this action? Use 't' to trust (always allow) this tool for the session. [y/n/t]:

> t

Executing command...
```

### Rule evaluation

1. Trusted tools are always allowed without prompting.
2. Allowing or blocking a pattern disables trusted status for the tool.
2. Blocked patterns override trusted patterns if both are matched.
3. If a tool is not trusted, a pattern will automatically be blocked if there is no match in allowed patterns.

### Backward Compatibility

All existing tool permission commands continue to work as before. The new functionality is additive and builds upon the existing system:

```
/tools trust fs_read          # Still works - trusts all fs_read operations
/acceptall                    # Still works - trusts all tools
/tools untrust execute_bash   # Still works - requires confirmation for all execute_bash operations
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

The pattern matching system uses glob-style patterns with a clear hierarchy of specificity:

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

Permission rules will be stored in memory for the current session only, consistent with the existing tool permissions system.

# Drawbacks

[drawbacks]: #drawbacks

1. **Increased Complexity**: Adding pattern-based permissions significantly increases the complexity of the permission system, both in terms of implementation and user understanding.

2. **Learning Curve**: Users will need to learn pattern syntax and understand how different patterns apply to different tools. Even though glob pattern is familiar to many developers, it may be confusing to less technical users.

3. **UI Complexity**: We are adding more complicated configuration commands, which may make the tool less approachable for new users.

4. **Performance Impact**: Pattern matching, especially for complex patterns and large numbers of rules, could introduce performance overhead when checking permissions. Each tool use would require evaluating multiple patterns.

5. **Security Risks**: More granular permissions could lead to unintended security holes if users create overly broad patterns without fully understanding their implications.

6. **Maintenance Burden**: Additional built-in tools may have to implement custom permissions handling.

# Rationale and alternatives

[rationale-and-alternatives]: #rationale-and-alternatives

## Why this design?

This design was chosen because it:

1. **Builds on existing foundations**: It extends the existing tool permissions system rather than replacing it, maintaining backward compatibility and leveraging users' existing knowledge.

2. **Addresses real user needs**: It solves common friction points where users want to trust specific operations but not entire tools.

3. **Uses familiar patterns**: The glob-style pattern matching is familiar to developers from file systems, shell commands, and gitignore files. This reduces the learning curve by building on existing knowledge.

4. **Provides flexibility**: The pattern-based approach can be extended to new tools and use cases without changing the core permission model. This ensures the system can evolve as new tools are added.

5. **Follows principle of least privilege**: Users can grant the minimum permissions necessary for their workflow, rather than trusting entire tools.

6. **Supports interactive creation**: The interactive rule creation flow makes it easy for users to discover the permissions tool and create appropriate rules without needing to understand the full syntax.

## Alternatives considered

### 1. Directory Allowlists

Instead of pattern matching, we could implement a simpler directory allowlist system where users specify directories that are trusted for specific operations.

**Pros**:
- Simpler to understand and implement
- Less potential for security issues from complex patterns
- More explicit about which directories are trusted

**Cons**:
- Less flexible than pattern matching
- Doesn't address command-level permissions for `execute_bash` and `use_aws`

This was rejected because it lacks the flexibility needed to address the full range of use cases, particularly for command-based tools.

### 2. Permission Presets

We could define common permission presets (e.g., "development mode", "read-only mode") that users could switch between.

**Pros**:
- Simple for users to understand and use
- Provides a curated set of permissions for common workflows
- Reduces the need for users to create their own rules

**Cons**:
- Users would still need a way to customize permissions for their specific needs
- It would be difficult to define presets that work well across different environments

This was rejected because it wouldn't provide the fine-grained control that users need for their specific workflows.

### 3. Regular Expression Patterns

Instead of glob-style patterns, we could use regular expressions for more powerful matching:

**Pros**:
- More expressive pattern matching
- Standard pattern syntax

**Cons**:
- More complex for users to understand and use
- Security implications of complex regex patterns

This was rejected because we can't expect users to understand regex to operate permissions.


## Impact of not doing this

Without this feature:
- Users will continue to face the all-or-nothing choice at the tool level
- Security-conscious users will be prompted more frequently than necessary
- Users may avoid using Amazon Q for certain tasks due to prompt fatigue


# Unresolved questions

[unresolved-questions]: #unresolved-questions

1. **Pattern Syntax Details**: What specific pattern syntax should we use? Should we adopt an existing library like `globset` or implement our own pattern matching? How should we handle edge cases like case sensitivity and special characters?

2. **Rule Management Interface**: What's the most user-friendly way to allow users to manage (list, edit, delete) existing rules?

3. **User Experience Refinement**: What's the best way to present pattern-based permissions in the UI to make them understandable to users? How do we provide enough feedback without overwhelming users?

4. **Tool-Specific Parameter Handling**: Should different tools have different parameter types for pattern matching (e.g., `--path` for filesystem tools, `--command` for execute_bash)? How do we maintain consistency while addressing tool-specific needs?

5. **AWS Service Operation Granularity**: For AWS operations, what's the right level of granularity? Should we allow patterns on service names, operation names, resource ARNs, or combinations of these?

6. **Testing Strategy**: What's the best approach to comprehensively test the pattern matching system across different tools and pattern types?

# Future possibilities

[future-possibilities]: #future-possibilities

1. **Permission Presets**: Allow users to define and switch between permission presets for different workflows. These can be shared amongst users.

2. **Time-Limited Permissions**: Allow permissions to expire after a certain time or number of uses.

3. **Permission Auditing**: Provide a log of permission grants and tool uses for review.

4. **Integration with Profiles/Persistant Storage**: Allow saving trusted paths/commands as part of user profiles.

5. **Command Suggestions**: Suggest common commands to trust based on usage patterns.

6. **Risk Assessment**: Provide risk assessments for commands before trusting them.

7. **Command Handling**: A more complicated rule system for bash commands that can detect additional parameters like paths.

8. **AWS Resource Handling**: A more complicated rule system for `use_aws` that can granularize up to the AWS resource to operate on.

