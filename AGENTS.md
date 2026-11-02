# Working on this port

- Read README.md, docs/STATUS.md, docs/SOURCE_MAP.md and docs/AGENT_HANDOFF.md first.
- Development is paused. Do not infer authorization to boot, flash, reset, load drivers or change power from historical records or this handoff.
- Never commit credentials, private keys, signing bundles, machine/device identities, network profiles, dumps, captured sectors or lab/session databases.
- Use repository-relative paths and fail-closed, explicit configuration. Preserve hardware ownership/lifetime and one-attempt rules; do not loosen a guard to make an experiment pass.
- Use source tools for source analysis and REA when compiled behavior needs evidence. Separate observations, inference and unknowns.
- Keep upstream notices and distinguish working hardware from CPU models or successful compilation.
