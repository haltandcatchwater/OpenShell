//! Channel→Policy mapper — compiles Fractal's typed channel declarations
//! into OpenShell YAML policy blocks.
//!
//! Fractal channels declare WHAT a cell can do (read files, HTTP GET, git commit).
//! OpenShell policies enforce HOW those capabilities are constrained at the
//! sandbox boundary (filesystem, network, process layers).
//!
//! Keeper channels (those where Fractal adds semantic scoping beyond what the
//! platform natively provides) are mapped. Channels that duplicate platform RBAC
//! (postgres roles, stripe restricted keys, AWS IAM) are deliberately skipped.

use crate::schema::TypedChannelConfig;
use openshell_policy::{FilesystemPolicy, NetworkPolicy, NetworkEndpoint, L7Rule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The result of mapping a single channel to policy blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MappingResult {
    Mapped(MappedChannel),
    Skipped(SkippedChannel),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedChannel {
    pub channel_name: String,
    pub filesystem: Option<FilesystemPolicy>,
    pub network_policies: BTreeMap<String, NetworkPolicy>,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedChannel {
    pub channel_name: String,
    pub kind: String,
    pub reason: String,
}

/// LLM provider default API hosts.
const LLM_HOSTS: &[(&str, &str)] = &[
    ("anthropic", "api.anthropic.com"),
    ("openai", "api.openai.com"),
    ("google-genai", "generativelanguage.googleapis.com"),
    ("cohere", "api.cohere.com"),
    ("mistral", "api.mistral.ai"),
];

/// Default binary path for Node.js in sandbox images.
const DEFAULT_BINARY: &str = "/usr/local/bin/node";

/// Channel kinds that are deliberately NOT mapped (duplicate platform RBAC).
const SKIPPED_KINDS: &[(&str, &str)] = &[
    ("postgres", "read-only via SQL inspection is unsound — use a Postgres read-only role"),
    ("sqlite", "read-only via SQL inspection is unsound — use a read-only DB file/role"),
    ("stripe", "duplicates Stripe's restricted-key + permission-scope model"),
    ("aws-s3", "duplicates AWS IAM — lean on roles, not JS bucket-scoping"),
    ("sqs", "duplicates AWS IAM"),
    ("docker", "native RBAC; JS re-scoping is a fragile duplicate"),
    ("kubernetes", "native RBAC; JS re-scoping is a fragile duplicate"),
    ("terraform", "native policy model; JS re-scoping is a fragile duplicate"),
    ("vault", "native policy model; JS re-scoping is a fragile duplicate"),
    ("github-actions", "native RBAC; JS re-scoping is a fragile duplicate"),
    ("browser", "allowedHosts overlaps OpenShell network policy — redundant"),
];

/// Map a single Fractal channel to OpenShell policy blocks.
pub fn map_channel(channel: &TypedChannelConfig) -> MappingResult {
    let kind = channel.kind.as_str();

    // Check skip list first
    if let Some(&(_, reason)) = SKIPPED_KINDS.iter().find(|(k, _)| *k == kind) {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: kind.to_string(),
            reason: reason.to_string(),
        });
    }

    match kind {
        "file" => map_file_channel(channel),
        "http" => map_http_channel(channel),
        "anthropic" | "openai" | "google-genai" | "cohere" | "mistral" => {
            map_llm_channel(channel, kind)
        }
        "github" => map_github_channel(channel),
        "git" => map_git_channel(channel),
        "package" => map_package_channel(channel),
        _ => MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: kind.to_string(),
            reason: format!(
                "unknown kind '{}' — not in the keeper set; skipped to avoid false assurance",
                kind
            ),
        }),
    }
}

/// Map all channels in a cell, collecting results.
pub fn map_all(channels: &[TypedChannelConfig]) -> Vec<MappingResult> {
    channels.iter().map(map_channel).collect()
}

/// Resolve template variables in paths. `${input.repoPath}` → `/sandbox`
/// (the default OpenShell workdir). Other `${input.X}` vars are preserved.
fn resolve_path(path: &str) -> String {
    path.replace("${input.repoPath}", "/sandbox")
}

fn map_file_channel(channel: &TypedChannelConfig) -> MappingResult {
    let allowed_paths: Vec<String> = str_arr(&channel.scope, "allowedPaths")
        .into_iter()
        .map(|p| resolve_path(&p))
        .collect();
    let protected_paths = str_arr(&channel.scope, "protectedPaths");
    let mut anomalies = Vec::new();

    if !protected_paths.is_empty() {
        anomalies.push(format!(
            "file channel '{}': protectedPaths cannot be expressed as deny-list \
             in OpenShell filesystem_policy. Ensure these paths are NOT granted \
             write access elsewhere.",
            channel.name
        ));
    }

    // Merge allowed paths with OpenShell sandbox defaults
    let mut rw = vec!["/sandbox".into(), "/tmp".into(), "/dev/null".into()];
    rw.extend(allowed_paths);
    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: Some(FilesystemPolicy {
            read_write: Some(rw),
            read_only: Some(vec![
                "/usr".into(), "/lib".into(), "/dev/urandom".into(),
                "/proc".into(), "/app".into(), "/etc".into(), "/var/log".into(),
            ]),
            ..Default::default()
        }),
        network_policies: BTreeMap::new(),
        anomalies,
    })
}

fn map_http_channel(channel: &TypedChannelConfig) -> MappingResult {
    let allowed_hosts = str_arr(&channel.scope, "allowedHosts");
    let allowed_methods = str_arr(&channel.scope, "allowedMethods");

    if allowed_hosts.is_empty() {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: "http".into(),
            reason: "no allowedHosts configured".into(),
        });
    }

    let rules: Vec<L7Rule> = allowed_methods
        .iter()
        .map(|m| L7Rule {
            allow: Some(openshell_policy::L7Allow {
                method: Some(m.to_uppercase()),
                path: None,
            }),
            deny: None,
        })
        .collect();

    let endpoints: Vec<NetworkEndpoint> = allowed_hosts
        .iter()
        .map(|h| NetworkEndpoint {
            host: h.clone(),
            port: Some(443),
            protocol: Some("rest".into()),
            tls: Some("terminate".into()),
            enforcement: Some("enforce".into()),
            rules: rules.clone(),
            ..Default::default()
        })
        .collect();

    let mut network_policies = BTreeMap::new();
    network_policies.insert(
        format!("fractal_http_{}", sanitize_name(&channel.name)),
        NetworkPolicy {
            name: format!("fractal_http_{}", channel.name),
            endpoints,
            binaries: binaries_from_scope(&channel.scope, &[DEFAULT_BINARY]),
            ..Default::default()
        },
    );

    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: None,
        network_policies,
        anomalies: Vec::new(),
    })
}

fn map_llm_channel(channel: &TypedChannelConfig, kind: &str) -> MappingResult {
    let default_host = LLM_HOSTS.iter().find(|(k, _)| *k == kind).map(|(_, h)| *h);
    let host = str_val(&channel.scope, "baseUrl")
        .and_then(|u| host_from_url(&u))
        .or(default_host.map(|h| h.to_string()));

    let Some(host) = host else {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: kind.to_string(),
            reason: "no host resolvable from baseUrl or defaults".into(),
        });
    };

    let rules = vec![L7Rule {
        allow: Some(openshell_policy::L7Allow {
            method: Some("POST".into()),
            path: Some("/v1/**".into()),
        }),
        deny: None,
    }];

    let endpoint = NetworkEndpoint {
        host,
        port: Some(443),
        protocol: Some("rest".into()),
        tls: Some("terminate".into()),
        enforcement: Some("enforce".into()),
        rules,
        ..Default::default()
    };

    let mut network_policies = BTreeMap::new();
    network_policies.insert(
        format!("fractal_{}_{}", kind, sanitize_name(&channel.name)),
        NetworkPolicy {
            name: format!("fractal_{}_{}", kind, channel.name),
            endpoints: vec![endpoint],
            binaries: binaries_from_scope(&channel.scope, &[DEFAULT_BINARY]),
            ..Default::default()
        },
    );

    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: None,
        network_policies,
        anomalies: vec![format!(
            "{} channel '{}': allowedModels/maxTokensPerCall/rate limits are Fractal-enforced \
             (app-semantic); OpenShell network policy only constrains host+method.",
            kind, channel.name
        )],
    })
}

/// GitHub operation → (HTTP method, path template). Mirrors the TypeScript
/// bridge's GITHUB_OP_MAP. Paths use /** as the repo placeholder.
const GITHUB_OP_MAP: &[(&str, &str, &str)] = &[
    ("createPR", "POST", "/repos/**/pulls"),
    ("mergePR", "PUT", "/repos/**/pulls/*/merge"),
    ("listPRs", "GET", "/repos/**/pulls"),
    ("getPR", "GET", "/repos/**/pulls/*"),
    ("createIssue", "POST", "/repos/**/issues"),
    ("listIssues", "GET", "/repos/**/issues"),
    ("getIssue", "GET", "/repos/**/issues/*"),
    ("commentOnIssue", "POST", "/repos/**/issues/*/comments"),
    ("closeIssue", "PATCH", "/repos/**/issues/*"),
    ("listRepos", "GET", "/user/repos"),
    ("getRepo", "GET", "/repos/**"),
    ("createRelease", "POST", "/repos/**/releases"),
];

fn map_github_channel(channel: &TypedChannelConfig) -> MappingResult {
    let allowed_repos = str_arr(&channel.scope, "allowedRepos");
    let allowed_operations = str_arr(&channel.scope, "allowedOperations");
    let mut anomalies: Vec<String> = Vec::new();
    let mut rules: Vec<L7Rule> = Vec::new();
    let mut unmapped: Vec<&str> = Vec::new();

    for op in &allowed_operations {
        let entry = GITHUB_OP_MAP.iter().find(|(k, _, _)| *k == op.as_str());
        match entry {
            Some(&(_, method, path)) => {
                if !allowed_repos.is_empty() {
                    // One rule per (operation, repo). Substitute /** with the
                    // repo, preserving the operation suffix.
                    for repo in &allowed_repos {
                        let substituted = path.replace("/**", &format!("/{}", repo));
                        rules.push(L7Rule {
                            allow: Some(openshell_policy::L7Allow {
                                method: Some(method.into()),
                                path: Some(substituted),
                            }),
                            deny: None,
                        });
                    }
                } else {
                    rules.push(L7Rule {
                        allow: Some(openshell_policy::L7Allow {
                            method: Some(method.into()),
                            path: Some(path.into()),
                        }),
                        deny: None,
                    });
                }
            }
            None => unmapped.push(op.as_str()),
        }
    }

    if !unmapped.is_empty() {
        anomalies.push(format!(
            "github channel \"{}\": operations {:?} have no L7 method/path mapping; emitted rules cover only the mapped subset.",
            channel.name, unmapped
        ));
    }

    if rules.is_empty() {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: "github".into(),
            reason: "no allowedOperations mapped to GitHub API endpoints".into(),
        });
    }

    let endpoint = NetworkEndpoint {
        host: "api.github.com".into(),
        port: Some(443),
        protocol: Some("rest".into()),
        tls: Some("terminate".into()),
        enforcement: Some("enforce".into()),
        rules,
        access: Some("read-only".into()),
        ..Default::default()
    };

    let mut network_policies = BTreeMap::new();
    network_policies.insert(
        format!("fractal_github_{}", sanitize_name(&channel.name)),
        NetworkPolicy {
            name: format!("fractal_github_{}", channel.name),
            endpoints: vec![endpoint],
            binaries: binaries_from_scope(&channel.scope, &[
                DEFAULT_BINARY,
                "/usr/bin/git",
                "/usr/local/bin/git",
            ]),
            ..Default::default()
        },
    );

    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: None,
        network_policies,
        anomalies,
    })
}

fn map_git_channel(channel: &TypedChannelConfig) -> MappingResult {
    let remotes = str_arr(&channel.scope, "allowRemotes");
    let hosts: Vec<String> = remotes
        .iter()
        .filter_map(|r| host_from_remote(r))
        .collect();

    if hosts.is_empty() {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: "git".into(),
            reason: "no allowRemotes hosts resolvable".into(),
        });
    }

    let endpoints: Vec<NetworkEndpoint> = hosts
        .iter()
        .map(|h| NetworkEndpoint {
            host: h.clone(),
            port: Some(443),
            protocol: Some("rest".into()),
            tls: Some("terminate".into()),
            enforcement: Some("enforce".into()),
            access: Some("read-write".into()),
            rules: Vec::new(),
            ..Default::default()
        })
        .collect();

    let mut network_policies = BTreeMap::new();
    network_policies.insert(
        format!("fractal_git_{}", sanitize_name(&channel.name)),
        NetworkPolicy {
            name: format!("fractal_git_{}", channel.name),
            endpoints,
            binaries: binaries_from_scope(&channel.scope, &[
                "/usr/bin/git",
                "/usr/local/bin/git",
                DEFAULT_BINARY,
            ]),
            ..Default::default()
        },
    );

    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: None,
        network_policies,
        anomalies: vec![format!(
            "git channel '{}': git can exfiltrate via commit+push. \
             Review allowRemotes carefully.",
            channel.name
        )],
    })
}

fn map_package_channel(channel: &TypedChannelConfig) -> MappingResult {
    let registries = str_arr(&channel.scope, "allowedRegistries");
    let hosts: Vec<String> = registries
        .iter()
        .filter_map(|r| host_from_registry(r))
        .collect();

    if hosts.is_empty() {
        return MappingResult::Skipped(SkippedChannel {
            channel_name: channel.name.clone(),
            kind: "package".into(),
            reason: "no allowedRegistries hosts resolvable".into(),
        });
    }

    let endpoints: Vec<NetworkEndpoint> = hosts
        .iter()
        .map(|h| NetworkEndpoint {
            host: h.clone(),
            port: Some(443),
            protocol: Some("rest".into()),
            tls: Some("terminate".into()),
            enforcement: Some("enforce".into()),
            access: Some("read-write".into()),
            rules: Vec::new(),
            ..Default::default()
        })
        .collect();

    let mut network_policies = BTreeMap::new();
    network_policies.insert(
        format!("fractal_package_{}", sanitize_name(&channel.name)),
        NetworkPolicy {
            name: format!("fractal_package_{}", channel.name),
            endpoints,
            binaries: binaries_from_scope(&channel.scope, &[
                DEFAULT_BINARY,
                "/usr/bin/npm",
                "/usr/bin/pnpm",
                "/usr/bin/yarn",
                "/usr/bin/pip3",
                "/usr/bin/uv",
            ]),
            ..Default::default()
        },
    );

    MappingResult::Mapped(MappedChannel {
        channel_name: channel.name.clone(),
        filesystem: None,
        network_policies,
        anomalies: vec![format!(
            "package channel '{}': lockfileEnforced/allowedPackages are Fractal-enforced \
             (app-semantic); OpenShell network policy only constrains the registry host.",
            channel.name
        )],
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn str_arr(scope: &serde_json::Value, key: &str) -> Vec<String> {
    scope
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn str_val(scope: &serde_json::Value, key: &str) -> Option<String> {
    scope.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn binaries_from_scope(scope: &serde_json::Value, fallback: &[&str]) -> Vec<openshell_policy::Binary> {
    let declared = str_arr(scope, "binaries");
    let paths: Vec<&str> = if declared.is_empty() {
        fallback.to_vec()
    } else {
        declared.iter().map(|s| s.as_str()).collect()
    };
    paths.iter().map(|p| openshell_policy::Binary { path: p.to_string() }).collect()
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn host_from_url(url: &str) -> Option<String> {
    url.parse::<url::Url>()
        .ok()
        .and_then(|u| u.host_str().map(String::from))
}

fn host_from_remote(remote: &str) -> Option<String> {
    if let Ok(u) = remote.parse::<url::Url>() {
        return u.host_str().map(String::from);
    }
    // scp-like: [user@]host:path
    let after_at = remote.split('@').last().unwrap_or(remote);
    after_at.split(':').next().map(String::from)
}

fn host_from_registry(registry: &str) -> Option<String> {
    let with_scheme = if registry.starts_with("http") {
        registry.to_string()
    } else {
        format!("https://{}", registry)
    };
    with_scheme.parse::<url::Url>().ok().and_then(|u| u.host_str().map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_file_channel() {
        let channel = TypedChannelConfig {
            name: "workspace".into(),
            kind: "file".into(),
            scope: serde_json::json!({
                "allowedPaths": ["./workspace/**"],
                "protectedPaths": [".env"]
            }),
        };
        let result = map_channel(&channel);
        match result {
            MappingResult::Mapped(m) => {
                assert!(m.filesystem.is_some());
                assert_eq!(m.anomalies.len(), 1); // protectedPaths warning
            }
            _ => panic!("expected Mapped"),
        }
    }

    #[test]
    fn test_skip_stripe_channel() {
        let channel = TypedChannelConfig {
            name: "billing".into(),
            kind: "stripe".into(),
            scope: serde_json::json!({}),
        };
        let result = map_channel(&channel);
        assert!(matches!(result, MappingResult::Skipped(_)));
    }

    #[test]
    fn test_map_anthropic_channel() {
        let channel = TypedChannelConfig {
            name: "claude".into(),
            kind: "anthropic".into(),
            scope: serde_json::json!({}),
        };
        let result = map_channel(&channel);
        match result {
            MappingResult::Mapped(m) => {
                assert_eq!(m.network_policies.len(), 1);
                let policy = m.network_policies.values().next().unwrap();
                assert_eq!(policy.endpoints[0].host, "api.anthropic.com");
            }
            _ => panic!("expected Mapped"),
        }
    }
}
