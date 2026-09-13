# Mermaid paste probe

## 1. Minimal

```mermaid
flowchart LR
    A --> B
```

## 2. The real Tier 0 baseline architecture

```mermaid
flowchart TD
    S[Synthetic device status] -->|plaintext HTTP with shared identifier| O[Local OTA service]
    R[Mutable release record] --> O
    O -->|plaintext HTTP firmware bytes| F[ESP32-C6 secondary slot]
    F --> M[Unsigned MCUboot]
    M --> Z[Zephyr application]
```

No authenticated trust boundary exists in this Tier 0 path.

## 3. A trust boundary, which every control tier needs

```mermaid
flowchart LR
    subgraph trusted[Manufacturer controlled]
        W[Offline release workstation]
    end
    subgraph untrusted[Attacker reachable]
        O[OTA service]
    end
    W -->|signed image| O
    O -->|HTTPS download| D[ESP32-C6]
    D --> B{MCUboot verifies signature}
    B -->|valid| Z[Zephyr application]
    B -->|invalid| X[Reject image]
```

## 4. Does a diagram survive a round trip

Export this page back to Markdown after pasting. Check whether section 2 comes
back as a `mermaid` fence or as something else.
