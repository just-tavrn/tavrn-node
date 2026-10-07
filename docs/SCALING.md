# Several instances of one node

Running one node as several instances behind a load balancer, with a shared PostgreSQL, data volume and Valkey, is
now described in the operator handbook: [Scaling with Valkey](HANDBOOK.md#scaling-with-valkey).

- Requirements, load balancer, voice, examples and failure behaviour:
  [Operating several instances](HANDBOOK.md#operating-several-instances)
- Settings (`TAVRN_CACHE_URL`, `TAVRN_INSTANCE_ID`, `TAVRN_INSTANCE_URL`) and command interactions:
  [Settings for several instances](HANDBOOK.md#settings-for-several-instances)
- How the instances act as one node: [How the instances act as one node](HANDBOOK.md#how-the-instances-act-as-one-node)
- Where every piece of in-memory state went: [Audit of the in-memory state](HANDBOOK.md#audit-of-the-in-memory-state)
