# Agent Context for Zen IdP

## Summary

Zen IdP is a declarative, zero-maintenance OIDC Identity Provider.

## How to Maintain This Document

Keep this file current and minimal. Update it only when repository-wide workflow, structure, or agent guidance changes. Do not turn it into a changelog. Use it exclusively to indicate truly relevant things in the codebase; don't include any minor details that are obvious or don't warrant documentation.

## Required Agent Behavior

- Always check available Skills and MCPs before acting so you know what capabilities are available for you to use.
- Always read `Taskfile.yml` to understand available `task` commands for the project; do not list those commands here.
- When assigned a task, do not respond or stop until the requested task is complete.
- Run `task ci` for code checks. If it fails, fix failures caused by your own changes until it passes; stay within the scope of your changes and ignore pre-existing unrelated failures.
- All code, code comments, inline documentation, commit messages, and any other text in the project MUST be written in English.

## Testing

Whenever possible, write tests that verify the expected behavior of the code being implemented. You must follow the following rules regarding testing:

- Write the unit tests close to the code they are testing; for example, if you have the file foo.go, you have to put all the unit tests inside foo_test.go.
- When creating tests for Go, use the testify package which is already installed in the project. Prioritize using "require" whenever possible instead of "assert" so that the tests fail quickly when something is wrong.
- Write high-value tests, focus on critical logic and relevant edge cases. Quality beats quantity; don't write tests just to inflate coverage; make sure every test adds real value.
- Treat tests as our primary tool to catch regressions. Write every test to guarantee long-term stability, correctness, functionality, and maintainability as the codebase evolves.
