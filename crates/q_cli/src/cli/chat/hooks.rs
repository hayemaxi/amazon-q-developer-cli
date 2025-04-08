use std::rc::Rc;

use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookType {
    Inline,
    // Addtional hooks as necessary
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Fail,    // Hook failure will prevent prompt from being sent
    Warn,    // Hook failure will log a warning but allow prompt to be sent
    Ignore,  // Hook failure will be silently ignored
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    pub name: String,
    pub r#type: HookType,
    pub enabled: Option<bool>,
    pub timeout_ms: Option<u64>,
    pub max_output_size: Option<usize>,
    pub criticality: Option<Criticality>,
    pub cache_ttl_seconds: Option<u64>,
    // Type-specific fields
    pub command: Option<String>,     // For inline hooks
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub conversation_start: Option<Vec<Hook>>,
    pub per_prompt: Option<Vec<Hook>>,
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