# Sinopia Github Auth plugin

### Features

* uses internal caching and conditional requests (ETag-based) to prevent rate limit exceeding
* github team names are available as Sinopia groups in config.yaml

### config.yaml

```
auth:
  github:
    org: medallia
    client_id: abc # register a new application with github to get your id and secret
    client_secret: 123
    ttl: 300
...
packages:
  'orgprefix-*':
    allow_access: $authenticated
    allow_publish: Team One, Team Five # these are the Github team names within your org
```
