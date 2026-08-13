# Product Lifecycle logic flow

## Register, release and sunset

```mermaid
stateDiagram-v2
    [*] --> Draft
    Draft --> Preview: register
    Draft --> GenerallyAvailable: release
    Preview --> GenerallyAvailable: release
    GenerallyAvailable --> Restricted: restrict
    GenerallyAvailable --> Deprecated: deprecate
    Restricted --> Deprecated: deprecate
    Restricted --> Withdrawn: withdraw
    Deprecated --> Withdrawn: withdraw
    GenerallyAvailable --> Withdrawn: withdraw
    Withdrawn --> Sunset: sunset
    Deprecated --> Sunset: sunset
```

`inspect` never changes stage. A public draft is rejected before any
transition.

## Catalog, legal pack and SaaS offer

```mermaid
sequenceDiagram
    participant C as Catalog
    participant L as Legal lifecycle
    participant S as SaaS lifecycle
    C->>L: check_availability for product legalPackRef
    L-->>C: offered, restricted or prohibited
    alt prohibited
        C-->>C: keep draft or mark restricted
    else offered
        C->>C: release to generally-available
        S->>C: bind productRef into a versioned offer
        S->>L: bind legalPolicyRef from the same pack
    end
```

Retries of `release` for the same `productRef` and catalog version are
idempotent. A later restriction does not rewrite history; it publishes a
new stage with a new state version.

## Failure routing

| Failure | Required state/outcome | Safe next action |
| --- | --- | --- |
| Public draft | `denied` | keep `public=false` until preview or GA |
| GA with every jurisdiction prohibited | `denied` | bind a legal pack that offers a location |
| Product succeeds itself | `denied` | name a different `productRef` |
| Request contains price or settlement | `denied` | move amounts to saas-lifecycle |
| Request contains hostname | `denied` | use opaque deployment refs |
| Sunset without `sunsetAt` | `failed` | add an explicit date |
| Active state with no offered location | `failed` | restrict or withdraw honestly |
| Receipt stores commercial data | `failed` | redact and re-issue |

No failure path stores a price or turns a transport-level success into a
generally-available product.
