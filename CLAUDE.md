# CLAUDE.md

This file is read automatically at the start of every session in this repo.

## Session protocol (do this every session)

1. **On session start**, read `PROJECT.md` in the repo root before doing anything else. It holds the current status, decisions, and next steps for this project — treat it as the source of truth for "where we left off," ahead of re-deriving state from git log or asking the user to repeat themselves.
2. **During the session**, when a decision is made, a milestone lands, or direction changes, update `PROJECT.md` rather than waiting until the end.
3. **Before ending a session** (or at a natural stopping point), append a dated entry to the "Session Log" section of `PROJECT.md`: what changed, what's next, any open questions. Keep entries short — a few lines, not a transcript.
4. `PROJECT.md` is tracked in git like any other file — commit it along with the related code changes when it makes sense, so history stays paired.
5. Don't duplicate architecture/status detail across both `PROJECT.md` and Claude's own persistent memory — memory is for durable *why* facts and user preferences that outlive this repo; `PROJECT.md` is the living project record. If they drift, `PROJECT.md` wins for anything code/status-related.

## Project

Gnark fork (`consensys/gnark`, base v0.16.3) adding **post-quantum polynomial commitment schemes** (FRI, Vortex, Basefold, Ligero/Brakedown — direction not yet fixed). gnark ships only KZG, which needs a trusted setup and is not PQ-secure.

See `PROJECT.md` for current architecture notes and status.
