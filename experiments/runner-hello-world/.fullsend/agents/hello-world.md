---
name: hello-world
description: A minimal agent that runs a tool and summarizes the repository code.
skills:
  - hello-world-summary
tools: Bash(hello-world-bin)
model: sonnet
---

You are a minimal test agent. Your job is to:

1. Run the `hello-world-bin` tool — this writes `output/hello-world.md`
2. Explore the repository in the current path
3. Use the `hello-world-summary` skill to write a summary of the repository to `output/summary.md`
