#!/usr/bin/env python3
"""Resolve pre-commit hook tool dependencies for a target repository.

Reads a target repo's .pre-commit-config.yaml, matches hooks against
the known-tools registry (.pre-commit-tools.yaml), and outputs a JSON
manifest to stdout.

Usage:
    resolve-precommit-tools.py <target-repo-path>
"""

import json
import os
import subprocess
import sys

try:
    import yaml
except ImportError:
    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--no-deps",
                "--break-system-packages",
                "pyyaml==6.0.2",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        import yaml
    except Exception:
        print('{"tools":[],"warnings":["failed to install pyyaml — cannot resolve hooks"]}')
        sys.exit(0)


def resolve(precommit_path: str, registry_path: str) -> dict:
    try:
        with open(precommit_path) as f:
            precommit = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as exc:
        return {"tools": [], "warnings": [f"failed to parse .pre-commit-config.yaml: {exc}"]}
    try:
        with open(registry_path) as f:
            registry = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as exc:
        return {"tools": [], "warnings": [f"failed to parse tools registry: {exc}"]}

    if not isinstance(precommit, dict) or "repos" not in precommit:
        return {"tools": [], "warnings": ["empty or invalid .pre-commit-config.yaml"]}

    repos = precommit["repos"]
    if not isinstance(repos, list):
        return {"tools": [], "warnings": ["repos field is not a list in .pre-commit-config.yaml"]}

    if not isinstance(registry, dict) or "tools" not in registry:
        return {"tools": [], "warnings": ["empty or invalid tools registry"]}

    registry_tools = registry.get("tools") or []

    repo_hook_map = {}
    entry_match_map = {}
    for tool in registry_tools:
        if not isinstance(tool, dict) or "hook_id" not in tool:
            continue
        key = (tool.get("repo", ""), tool["hook_id"])
        repo_hook_map[key] = tool
        if "match_entry" in tool:
            entry_match_map[tool["match_entry"]] = tool

    resolved = []
    seen_names: set[str] = set()
    warnings = []

    for repo_entry in repos:
        if not isinstance(repo_entry, dict):
            continue
        repo_url = repo_entry.get("repo", "")
        for hook in repo_entry.get("hooks") or []:
            if not isinstance(hook, dict):
                continue
            hook_id = hook.get("id", "")
            entry = hook.get("entry", "")
            language = hook.get("language", "")

            tool = repo_hook_map.get((repo_url, hook_id))

            if tool is None and repo_url == "local":
                parts = entry.split()
                entry_cmd = parts[0] if parts else ""
                for match_str, match_tool in entry_match_map.items():
                    if entry_cmd == match_str:
                        tool = match_tool
                        break

            if tool is not None:
                install = tool.get("install") or {}
                name = install.get("name", "")
                if name and name not in seen_names:
                    seen_names.add(name)
                    resolved.append(install)
            else:
                if language == "system":
                    parts = entry.split()
                    cmd = parts[0] if parts else hook_id
                    warnings.append(
                        f"hook '{hook_id}' uses language:system "
                        f"(command: {cmd}) — not in registry, "
                        f"must be pre-installed on runner"
                    )
                elif language in ("golang",):
                    warnings.append(
                        f"hook '{hook_id}' requires Go toolchain (language: {language})"
                    )
                elif language in ("rust",):
                    warnings.append(
                        f"hook '{hook_id}' requires Rust toolchain (language: {language})"
                    )

    return {"tools": resolved, "warnings": warnings}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target-repo-path>", file=sys.stderr)
        sys.exit(1)

    target_repo = sys.argv[1]
    precommit_config = os.path.join(target_repo, ".pre-commit-config.yaml")

    if not os.path.isfile(precommit_config):
        print('{"tools":[],"warnings":["no .pre-commit-config.yaml found"]}')
        sys.exit(0)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    registry = os.path.join(script_dir, ".pre-commit-tools.yaml")

    if not os.path.isfile(registry):
        print('{"tools":[],"warnings":["tools registry not found"]}')
        sys.exit(0)

    result = resolve(precommit_config, registry)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
