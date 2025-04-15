- Feature Name: extra_granular_permissions
- Start Date: 2025-04-14

# Summary

[summary]: #summary

This RFC proposes extending the existing granular tool permissions system to provide even finer control over tool execution. It introduces path-based permissions for filesystem operations, command and argument-level permissions for the `execute_bash` tool, and a pattern-matching system that allows users to trust specific operation patterns without requiring confirmation for every similar action.

# Motivation

[motivation]: #motivation

While the current granular tool permissions system (RFC-0002) allows users to trust specific tools for the entire session, it still operates at a coarse level. Users must either trust a tool completely or approve each individual use. This creates friction in common workflows where users might want to:

1. Trust filesystem operations only within specific project directories
2. Allow certain shell commands but not others
3. Trust specific command patterns (e.g., `git status` but not other git commands)
4. Reduce interruptions for repetitive but safe operations

By providing more granular control, we can improve user experience by reducing unnecessary prompts while maintaining security for sensitive operations.

# Guide-level explanation

[guide-level-explanation]: #guide-level-explanation

## Overview

The extra granular permissions system builds upon the existing tool permissions framework by adding pattern-based rules that can be applied to specific tools. These rules define conditions under which a tool can execute without requiring explicit user confirmation.

## Key Concepts

### Path-Based Permissions

Users can specify trusted paths for filesystem operations:

```
/tools trust fs_read --path=/Volumes/workplace/myproject/**
/tools trust fs_write --path=/Volumes/workplace/myproject/output/**
```

This allows Amazon Q to read any files within the `myproject` directory and write only to the `output` subdirectory without prompting for confirmation.

### Command-Based Permissions for Shell Execution

For the `execute_bash` tool, users can specify trusted commands or command patterns:

```
/tools trust execute_bash --command="git status"
/tools trust execute_bash --command="ls **"
```

This allows Amazon Q to run `git status` or any `ls` command without confirmation, while still prompting for other commands.

### Permission Rules UI

Users can view and manage their permission rules:

```
> /tools rules
Current permission rules:
- fs_read: /Volumes/workplace/myproject/** (Trusted)
- fs_write: /Volumes/workplace/myproject/output/** (Trusted)
- execute_bash: git status (Trusted)
- execute_bash: ls ** (Trusted)
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
```

Where:
- `y` = Allow this specific request
- `n` = Deny this specific request
- `t` = Trust this tool for the session (no more prompts for this tool)
- `r` = Create a custom rule for this tool

## Backward Compatibility

All existing tool permission commands continue to work as before. The new functionality is additive and builds upon the existing system.

# Reference-level explanation

[reference-level-explanation]: #reference-level-explanation

## Data Structures

We'll extend the existing `ToolPermission` structure to support pattern-based rules:

```rust
/// Represents a pattern-based permission rule
struct PermissionRule {
    /// The pattern to match against (path, command, etc.)
    pattern: String,
    /// Whether this rule grants permission when matched
    is_allowed: bool,
}

/// Enhanced tool permission structure
struct ToolPermission {
    /// Whether the entire tool is trusted (from RFC-0002)
    trusted: bool,
    /// Path-based rules for filesystem tools
    path_rules: Vec<PermissionRule>,
    /// Command-based rules for execute_bash
    command_rules: Vec<PermissionRule>,
}

struct ToolPermissions {
    permissions: HashMap<String, ToolPermission>,
}
```

## Pattern Matching System

The pattern matching system will use glob-style patterns:

- `*` matches any sequence of characters within a path component
- `**` matches zero or more path components
- Exact matches take precedence over pattern matches

For command patterns:
- Command patterns are split into the command name and arguments
- `command **` would match any invocation of that command regardless of arguments
- `command arg1 *` would match the command with arg1 and any single additional argument

## Permission Checking Logic

The permission checking flow will be enhanced:

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
        _ => false,
    }
}

fn check_path_permission(&self, permission: &ToolPermission, path: &str) -> bool {
    for rule in &permission.path_rules {
        if self.pattern_matches(&rule.pattern, path) {
            return rule.is_allowed;
        }
    }
    false
}

fn check_command_permission(&self, permission: &ToolPermission, command: &str) -> bool {
    for rule in &permission.command_rules {
        if self.pattern_matches(&rule.pattern, command) {
            return rule.is_allowed;
        }
    }
    false
}

fn pattern_matches(&self, pattern: &str, value: &str) -> bool {
    // Implementation of glob-style pattern matching
    // This would use a library like globset or similar
    // ...
}
```

## Command Parsing

The `/tools` command will be extended to support the new rule-based syntax:

```rust
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
        "rules" => {
            self.show_permission_rules()?;
        },
        // Other existing commands...
        _ => {
            self.output_tools_help()?;
        }
    }
    
    Ok(())
}

fn handle_pattern_trust(&mut self, tool_name: &str, args: &[&str]) -> Result<()> {
    // Parse arguments like --path=/some/path or --command="git status"
    // ...
}
```

## UI Enhancements

The tool execution prompt will be enhanced to support rule creation:

```rust
fn prompt_for_tool_execution(&mut self, tool_name: &str, params: &Value) -> Result<ToolPromptResponse> {
    execute!(
        self.output,
        style::SetForegroundColor(Color::Yellow),
        style::Print(format!("[Tool Request: {} ({})]\n", tool_name, params)),
        style::Print("Allow this action? [y/n/t/r]: "),
        style::SetForegroundColor(Color::Reset)
    )?;
    
    // Read user input
    let response = self.read_line()?;
    
    match response.trim().to_lowercase().as_str() {
        "y" => Ok(ToolPromptResponse::Yes),
        "n" => Ok(ToolPromptResponse::No),
        "t" => Ok(ToolPromptResponse::Trust),
        "r" => {
            self.handle_rule_creation(tool_name, params)?;
            Ok(ToolPromptResponse::Yes)
        },
        _ => {
            // Handle invalid input
            // ...
        }
    }
}

fn handle_rule_creation(&mut self, tool_name: &str, params: &Value) -> Result<()> {
    // Interactive rule creation UI
    // ...
}
```

## Storage

Permission rules will be stored in memory for the current session only, consistent with the existing tool permissions system. This avoids persistent security risks while providing convenience within a session.

# Drawbacks

[drawbacks]: #drawbacks

1. **Increased Complexity**: Adding pattern-based permissions significantly increases the complexity of the permission system, both in terms of implementation and user understanding.

2. **Learning Curve**: Users will need to learn pattern syntax and understand how different patterns apply to different tools.

3. **UI Complexity**: The command-line interface becomes more complex with additional options and parameters.

4. **Performance Impact**: Pattern matching, especially for complex patterns, could introduce performance overhead when checking permissions.

5. **Security Risks**: More granular permissions could lead to unintended security holes if users create overly broad patterns without fully understanding their implications.

6. **Maintenance Burden**: The increased complexity will require more testing and maintenance effort, especially as new tools are added to the system.

# Rationale and alternatives

[rationale-and-alternatives]: #rationale-and-alternatives

## Why this design?

This design was chosen because it:

1. **Builds on existing foundations**: It extends the existing tool permissions system rather than replacing it, maintaining backward compatibility.

2. **Addresses real user needs**: It solves common friction points where users want to trust specific operations but not entire tools.

3. **Uses familiar patterns**: The glob-style pattern matching is familiar to developers from file systems, shell commands, and gitignore files.

4. **Balances security and convenience**: It maintains the security principle of explicit permission while reducing unnecessary interruptions.

5. **Provides flexibility**: The pattern-based approach can be extended to new tools and use cases without changing the core permission model.

## Alternatives considered

### 1. Directory Allowlists

Instead of pattern matching, we could implement a simpler directory allowlist system where users specify directories that are trusted for specific operations.

This was rejected because:
- It's less flexible than pattern matching
- It doesn't address command-level permissions for `execute_bash`
- It would require a separate permission model for each tool type

### 2. Permission Presets

We could define common permission presets (e.g., "development mode", "read-only mode") that users could switch between.

This was rejected because:
- Presets would be too generic for many workflows
- Users would still need a way to customize permissions for their specific needs
- It would be difficult to define presets that work well across different environments

### 3. Persistent Permissions

We could store permission rules in user profiles, making them persistent across sessions.

This was rejected because:
- It introduces long-term security risks if users forget which patterns they've trusted
- Session-based permissions provide a good balance between convenience and security
- It would require additional storage and management code

### 4. Do Nothing

We could keep the current tool-level permissions without adding pattern-based rules.

Impact of not doing this:
- Users would continue to face interruptions for repetitive but safe operations
- The user experience would remain suboptimal for common development workflows
- Users might be tempted to trust entire tools when they only need to trust specific operations

# Unresolved questions

[unresolved-questions]: #unresolved-questions

1. **Pattern Syntax**: What specific pattern syntax should we use? Should we adopt an existing library like `globset` or implement our own pattern matching?

2. **Command Parsing**: How should we parse and match shell commands, especially considering shell quoting and variable expansion?

3. **Rule Precedence**: How should conflicting rules be resolved? Should negative rules (denying access) take precedence over positive rules?

4. **Rule Management**: How should users manage (list, edit, delete) existing rules? Should there be a way to export/import rules?

5. **Performance Optimization**: How can we optimize pattern matching to minimize performance impact, especially for large numbers of rules?

6. **User Experience**: What's the best way to present pattern-based permissions in the UI to make them understandable to users?

7. **Tool-Specific Parameters**: Should different tools have different parameter types for pattern matching (e.g., `--path` for filesystem tools, `--command` for execute_bash)?

# Future possibilities

[future-possibilities]: #future-possibilities

1. **Persistent Rule Storage**: Allow users to save trusted patterns across sessions, perhaps with an expiration mechanism for security.

2. **Rule Templates**: Provide pre-defined rule templates for common development workflows (e.g., "Python development", "Web development").

3. **Time-Limited Rules**: Allow rules to expire after a certain time period or number of uses.

4. **Contextual Rules**: Make rules that only apply in certain contexts, such as when working in specific directories or with specific files open.

5. **Rule Sharing**: Allow teams to share permission rule sets for collaborative projects.

6. **Visual Rule Builder**: Create a visual interface for building and testing permission patterns.

7. **Rule Analytics**: Provide insights into which rules are frequently used or rarely matched.

8. **Integration with Other Security Features**: Integrate with other security features like code signing or integrity checking.

9. **Tool-Specific Rule Extensions**: Develop specialized rule types for new tools as they are added to the system.

10. **Permission Auditing**: Add logging of permission decisions to help users understand and refine their rule sets.
