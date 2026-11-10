# bm-messaging

> **Status: experimental spike. Not a product, not deployed, not supported.**
>
> Everything currently in this repository is exploratory work to answer a
> feasibility question about BrandMeister messaging. Nothing here is in
> production use, nothing is deployed to the cluster, and no interface in this
> repository should be treated as stable. Code may be rewritten or deleted
> without notice.

## What this repository is exploring

Whether SMS text messages on the BrandMeister DMR network can be received and
sent on behalf of individual RadioIDs (DMR IDs) by software, without radio
hardware, a repeater, or an RF path.

The conclusion so far, established against the live network rather than from
documentation: BrandMeister publishes no interface for reading SMS, but it does
operate the **Open DMR Terminal Protocol** (Rewind) on master UDP port `54006`,
intended for IP-based terminals. That protocol carries text messaging in both
directions and works as documented for receiving.

## Current contents

- `spike/` — a receive-only protocol spike for a single DMR ID. See
  `spike/README.md` for the verified behaviour, the protocol findings, and the
  credential requirements.

`AGENTS.md` describes development and deployment conventions for when this work
becomes a real service. Those conventions do not yet apply to anything here,
because nothing here is deployable: there is no container image, no Helm chart,
no Fleet bundle, no database schema, and no infrastructure manifest. The spike is
a local Python script.

## Caveats

- The spike is **receive only**. There is no transmission path, by design.
- It has been exercised against one DMR ID on one master. It is not proven at
  scale, across masters, or against protocol changes.
- The protocol specification is marked **DRAFT** by BrandMeister and observable
  behaviour already deviates from it in at least two ways, both documented in
  `spike/README.md`.
- Credentials are supplied through the environment and are never committed. Any
  real service will need a considered credential-custody design before it stores
  per-user secrets.
