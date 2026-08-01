#![allow(missing_docs)]

use serde_json::json;
use trusted_router::{
    advisor_tool, map_reduce_tool, selector_tool, subagent_tool, synth_tool, AdvisorToolOptions,
    MapReduceToolOptions, SelectionStrategy, SelectorToolOptions, SubagentToolOptions,
    SynthToolOptions,
};

#[test]
fn orchestration_builders_emit_stable_primitive_shapes() {
    let synth = synth_tool(SynthToolOptions {
        enabled: Some(false),
        analysis_models: vec!["a".to_owned(), "b".to_owned()],
        selection_strategy: Some(SelectionStrategy::SynthesizeNonRefusals),
        ..SynthToolOptions::default()
    });
    assert_eq!(synth["type"], "trustedrouter:fusion");
    assert_eq!(synth["parameters"]["enabled"], false);
    assert_eq!(
        synth["parameters"]["selection_strategy"],
        "synthesize_non_refusals"
    );

    assert_eq!(
        advisor_tool(AdvisorToolOptions {
            worker_models: vec!["worker".to_owned()],
            advisor_models: vec!["advisor".to_owned()],
            depth: Some(2),
            enabled: Some(true),
            worker_timeout_ms: Some(45_000),
            auto_initial_advice: Some(true),
            ..AdvisorToolOptions::default()
        }),
        json!({"type": "trustedrouter:advisor", "parameters": {
            "depth": 2, "enabled": true, "worker_models": ["worker"],
            "advisor_models": ["advisor"], "worker_timeout_ms": 45000,
            "auto_initial_advice": true
        }})
    );
    assert_eq!(
        selector_tool(SelectorToolOptions {
            enabled: Some(true),
            ..Default::default()
        })["parameters"]["enabled"],
        true
    );
    assert_eq!(
        selector_tool(SelectorToolOptions::default())["type"],
        "trustedrouter:selector"
    );
    assert_eq!(
        map_reduce_tool(MapReduceToolOptions {
            enabled: Some(true),
            ..Default::default()
        })["parameters"]["enabled"],
        true
    );
    assert_eq!(
        map_reduce_tool(MapReduceToolOptions::default())["type"],
        "trustedrouter:mapreduce"
    );
    assert_eq!(
        subagent_tool(SubagentToolOptions {
            enabled: Some(true),
            reasoning: Some(json!({"effort": "high"})),
            ..Default::default()
        })["parameters"]["reasoning"],
        json!({"effort": "high"})
    );
    assert_eq!(
        subagent_tool(SubagentToolOptions::default())["type"],
        "trustedrouter:subagent"
    );
}
