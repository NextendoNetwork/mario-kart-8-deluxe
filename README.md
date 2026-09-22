<h1 align="center">mario-kart-8-deluxe</h1>

<p align="center">
  <b>Nextendo Network game server for Mario Kart 8 Deluxe.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-orange" alt="License: PolyForm Shield 1.0.0">
  <img src="https://img.shields.io/badge/go-1.23%2B-00ADD8" alt="Go 1.23+">
</p>

---

## What is this?

The NEX game server for **Mario Kart 8 Deluxe** on [Nextendo Network](https://nextendo.network).
It handles authentication, matchmaking, and the in-game online session (worldwide races and
in-game lobbies), speaking the same NEX protocol the retail servers did.

It is built on the [**nextendo-nex**](https://github.com/NextendoNetwork/nextendo-nex) core, which
provides the PRUDP transport, RMC layer, and common service protocols.

## Running

```sh
cp example.env .env    # then edit .env
go run .
```

Configuration is entirely through environment variables: see [`example.env`](example.env). No
secrets are baked into the source: the auth/secure password, internal key, and token secret are all
read from the environment at startup.

## What this is not

This server ships **no** Nintendo code, keys, or copyrighted assets. It is an independent
reimplementation for use with a community-run replacement service, not affiliated with, endorsed by,
or associated with Nintendo. The NEX access key it uses is a well-known per-title value derivable
from the game itself, not a secret.

## License

Released under the **[PolyForm Shield License 1.0.0](LICENSE.md)**, source-available: read, use,
modify, and self-host, but do not use it to provide a product that competes with Nextendo Network.
