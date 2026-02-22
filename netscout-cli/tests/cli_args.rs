//! Integration tests for CLI argument parsing.
//! These tests verify that clap parses arguments correctly without
//! actually making network calls.

use std::process::Command;

fn netscout_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netscout"))
}

#[test]
fn test_help_flag() {
    let output = netscout_bin().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netscout"));
}

#[test]
fn test_version_flag() {
    let output = netscout_bin().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netscout"));
}

#[test]
fn test_no_subcommand_shows_help() {
    let output = netscout_bin().output().unwrap();
    // Should exit with error (missing subcommand)
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage") || stderr.contains("subcommand"));
}

#[test]
fn test_ping_help() {
    let output = netscout_bin().args(["ping", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("count"));
    assert!(stdout.contains("interval"));
    assert!(stdout.contains("timeout"));
}

#[test]
fn test_dns_help() {
    let output = netscout_bin().args(["dns", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DOMAIN"));
    assert!(stdout.contains("resolver"));
}

#[test]
fn test_port_help() {
    let output = netscout_bin().args(["port", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ports"));
    assert!(stdout.contains("parallel"));
}

#[test]
fn test_trace_help() {
    let output = netscout_bin().args(["trace", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("max-hops"));
}

#[test]
fn test_http_help() {
    let output = netscout_bin().args(["http", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("URL"));
    assert!(stdout.contains("method"));
    assert!(stdout.contains("follow"));
}

#[test]
fn test_cert_help() {
    let output = netscout_bin().args(["cert", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HOST"));
    assert!(stdout.contains("port"));
}

#[test]
fn test_speed_help() {
    let output = netscout_bin().args(["speed", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("download-only"));
}

#[test]
fn test_whois_help() {
    let output = netscout_bin().args(["whois", "--help"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_scan_help() {
    let output = netscout_bin().args(["scan", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("subnet"));
}

#[test]
fn test_netif_help() {
    let output = netscout_bin().args(["netif", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("up-only"));
}

#[test]
fn test_netif_runs_successfully() {
    let output = netscout_bin().args(["netif"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("INTERFACES"));
}

#[test]
fn test_netif_json() {
    let output = netscout_bin().args(["--json", "netif"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert!(parsed["interfaces"].is_array());
    assert!(parsed["total"].is_number());
}

#[test]
fn test_netif_up_only() {
    let output = netscout_bin()
        .args(["netif", "--up-only"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_unknown_subcommand() {
    let output = netscout_bin().args(["foobar"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_global_json_flag() {
    // --json is global and should be accepted before subcommand
    let output = netscout_bin().args(["--json", "netif"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_ping_missing_target() {
    let output = netscout_bin().args(["ping"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_dns_missing_domain() {
    let output = netscout_bin().args(["dns"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_global_table_flag() {
    let output = netscout_bin().args(["--table", "netif"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Table output should have column headers
    assert!(stdout.contains("NAME"));
    assert!(stdout.contains("STATE"));
    assert!(stdout.contains("MTU"));
}

#[test]
fn test_global_csv_flag() {
    let output = netscout_bin().args(["--csv", "netif"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // CSV output should have header row with commas
    assert!(stdout.contains("name,state,type,mtu,addresses"));
    // Should have at least one data row
    assert!(stdout.lines().count() >= 2);
}

#[test]
fn test_csv_netif_parseable() {
    let output = netscout_bin().args(["--csv", "netif"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // Header
    assert_eq!(lines[0], "name,state,type,mtu,addresses");
    // Each data row should have at least 4 commas (5 fields)
    for line in &lines[1..] {
        assert!(
            line.matches(',').count() >= 4,
            "CSV row should have at least 5 fields: {line}"
        );
    }
}

#[test]
fn test_ping_port_flag_help() {
    let output = netscout_bin().args(["ping", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--port"));
}
