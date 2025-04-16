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
