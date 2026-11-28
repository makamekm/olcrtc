# Working in this repository

- Work directly on the repository's default branch, `master`. Start by checking the local branch and its upstream. Integrate upstream updates without rewriting shared history.
- Commit every completed task's source changes, tests, build inputs, and documentation together on `master`. Run the relevant tests before committing and push the completed commits to `origin/master`. Verify the remote branch contains the commits before reporting completion.
- Keep secrets, private connection tokens, and incidental build output out of Git. Document the exact source revisions, toolchain, and build steps needed to reproduce any deployed build.
