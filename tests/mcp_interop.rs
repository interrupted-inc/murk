// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real MCP-client interop test: drives `murk mcp` with the official rmcp
//! client (not hand-crafted JSON-RPC) to prove a real client can connect,
//! handshake, list tools, and call tools — with scope enforcement holding
//! over the real transport.

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ContentBlock},
    object,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use tokio::process::Command;

#[tokio::test]
async fn mcp_client_lists_and_calls_tools() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--vault", "test.murk"])
        .write_stdin("interop-secret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "add",
            "OTHER_KEY",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .write_stdin("other-secret\n")
        .assert()
        .success();

    let grant = dir.path().join("grant.key");
    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "probe",
            "--only",
            "API_KEY",
            "--allow-tag",
            "agents",
            "--out",
            grant.to_str().unwrap(),
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let transport =
        TokioChildProcess::new(Command::new(env!("CARGO_BIN_EXE_murk")).configure(|cmd| {
            for var in MURK_CONTEXT_VARS {
                cmd.env_remove(var);
            }
            cmd.arg("mcp")
                .arg("--vault")
                .arg("test.murk")
                .current_dir(dir.path())
                .env("HOME", dir.path())
                .env("XDG_RUNTIME_DIR", dir.path())
                .env("MURK_KEY_FILE", grant.to_str().unwrap())
                .env("MURK_AGENT", "1");
        }))
        .unwrap();

    let client = ().serve(transport).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"murk_plan"), "tools: {names:?}");
    assert!(names.contains(&"murk_get"), "tools: {names:?}");

    let in_scope = client
        .call_tool(
            CallToolRequestParams::new("murk_get").with_arguments(object!({ "key": "API_KEY" })),
        )
        .await
        .unwrap();
    assert_ne!(in_scope.is_error, Some(true));
    let in_scope_text: String = in_scope
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(in_scope_text, "interop-secret");

    let out_of_scope = client
        .call_tool(
            CallToolRequestParams::new("murk_get").with_arguments(object!({ "key": "OTHER_KEY" })),
        )
        .await
        .unwrap();
    assert_eq!(out_of_scope.is_error, Some(true));
    let out_of_scope_text: String = out_of_scope
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect();
    assert!(
        !out_of_scope_text.contains("other-secret"),
        "leaked out-of-scope value: {out_of_scope_text}"
    );

    client.cancel().await.unwrap();
}

#[test]
fn mcp_refuses_to_start_with_an_expired_grant() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("interop-secret\n")
        .assert()
        .success();
    let grant = dir.path().join("grant.key");
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "mcp", "--only", "API_KEY", "--ttl", "3s",
        ])
        .arg("--out")
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    // A 1s TTL could lapse before a slow (loaded, debug) mint saves, and the
    // save would then prune the grant: the read would fail for the wrong reason.
    std::thread::sleep(std::time::Duration::from_millis(3100));

    common::murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &grant)
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin("")
        .assert()
        .failure()
        .stdout("")
        .stderr(predicates::str::contains("grant mcp expired"));
}
