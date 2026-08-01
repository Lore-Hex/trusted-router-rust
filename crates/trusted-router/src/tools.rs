//! `TrustedRouter` orchestration tool builders.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Synth answer-selection behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Synthesize all panel answers.
    Synthesize,
    /// Synthesize only non-refusal panel answers.
    SynthesizeNonRefusals,
    /// Return the first successful answer.
    FirstSuccess,
    /// Return the first successful non-refusal answer.
    FirstNonRefusal,
}

/// Parameters for the Synth primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SynthToolOptions {
    /// Explicitly enables or disables this tool on a concrete model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Parallel panel models.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analysis_models: Vec<String>,
    /// Primary judge/synthesizer model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Selection strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_strategy: Option<SelectionStrategy>,
    /// Judge fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_judges: Vec<String>,
    /// Final synthesizer fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_final_models: Vec<String>,
    /// Maximum visible completion tokens per call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    /// Maximum tool calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<u32>,
    /// Named server preset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Optional panel prompt addition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panel_prompt: Option<String>,
    /// Optional final synthesis prompt addition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synthesis_prompt: Option<String>,
}

/// Builds a `trustedrouter:fusion` tool accepted by both Synth and Fusion aliases.
pub fn synth_tool(options: SynthToolOptions) -> Value {
    json!({"type": "trustedrouter:fusion", "parameters": options})
}

/// Parameters for the Advisor primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvisorToolOptions {
    /// Explicitly enables or disables this tool on a concrete model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Recursion depth, default 2 and maximum 4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u8>,
    /// Worker model fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_models: Vec<String>,
    /// Advisor model fallback chain. Advisors run in parallel when supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisor_models: Vec<String>,
    /// Maximum internal advice calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_get_advice_calls: Option<u8>,
    /// Maximum advisor output tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisor_max_tokens: Option<u32>,
    /// Worker deadline in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_timeout_ms: Option<u64>,
    /// Advisor deadline in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisor_timeout_ms: Option<u64>,
    /// Ask the advisor before the first worker turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_initial_advice: Option<bool>,
}

/// Builds a `trustedrouter:advisor` tool.
pub fn advisor_tool(options: AdvisorToolOptions) -> Value {
    json!({"type": "trustedrouter:advisor", "parameters": options})
}

/// Parameters for the Selector primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SelectorToolOptions {
    /// Explicitly enables or disables this tool on a concrete model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Models that answer in parallel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analysis_models: Vec<String>,
    /// Selector fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_models: Vec<String>,
    /// Additional selector instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_prompt: Option<String>,
    /// Maximum completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
}

/// Builds a `trustedrouter:selector` tool.
pub fn selector_tool(options: SelectorToolOptions) -> Value {
    json!({"type": "trustedrouter:selector", "parameters": options})
}

/// Parameters for the `MapReduce` primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MapReduceToolOptions {
    /// Explicitly enables or disables this tool on a concrete model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Mapper fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapper_models: Vec<String>,
    /// Parallel worker fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parallel_models: Vec<String>,
    /// Reducer fallback chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reducer_models: Vec<String>,
    /// Maximum parallel parts, capped by the API at eight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_parts: Option<u8>,
    /// Additional mapper instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapper_prompt: Option<String>,
    /// Additional worker instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_prompt: Option<String>,
    /// Additional reducer instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reducer_prompt: Option<String>,
    /// Maximum completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
}

/// Builds a `trustedrouter:mapreduce` tool.
pub fn map_reduce_tool(options: MapReduceToolOptions) -> Value {
    json!({"type": "trustedrouter:mapreduce", "parameters": options})
}

/// Parameters for the Subagent primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubagentToolOptions {
    /// Explicitly enables or disables this tool on a concrete model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Outer controller model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_model: Option<String>,
    /// Delegated worker model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Additional private controller instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Recursion depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u8>,
    /// Maximum delegated calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_subagent_calls: Option<u8>,
    /// Maximum worker completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    /// Worker temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Optional provider reasoning configuration for delegated calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<Value>,
    /// Optional worker server tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
}

/// Builds a `trustedrouter:subagent` tool.
pub fn subagent_tool(options: SubagentToolOptions) -> Value {
    json!({"type": "trustedrouter:subagent", "parameters": options})
}
