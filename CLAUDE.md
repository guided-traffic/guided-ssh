# guided-ssh

## Project orientation

I (Claude) use graphify myself to get oriented in the project quickly — not just
on request. Approach:

- **At session start / for unfamiliar code**: check the existing knowledge graph
  in `graphify-out/` first (`GRAPH_REPORT.md` for god nodes/communities,
  `graph.json` for details) instead of blindly searching files. Ask targeted
  questions: `/graphify query "<question>"`, `/graphify path "<A>" "<B>"`,
  `/graphify explain "<node>"`.
- **Graph missing or stale**: `/graphify .` (full build) or `/graphify . --update`
  (changed files only; no LLM for pure code changes). Keep it current after
  larger changes.
- `graphify-out/` is a working artifact (don't commit it unless told otherwise).

ONLY UPDATE GRAPHIFY IF TOLD SO.

## Project context

- Plan and progress: `INITIAL_PROJECT_PLAN.md` (phases with checkable steps — check off what's done)
- When you finish a task, also print a short conventional commit message

## Language policy

- The entire project is written in English: code, comments, docs, UI, everything.
- If you find German text anywhere, don't translate it on the spot — flag it and
  ask how to proceed first, then translate to English once confirmed.
