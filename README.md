# Cookie Center

Cookie Center is a Burp Suite extension for managing request cookies by host.

## Features

- Store one cookie header value per host.
- Enable or disable entries without deleting them.
- Choose whether an entry also applies to subdomains.
- Import host and cookie values from common curl command formats.
- Replace existing entries for the same host instead of creating duplicates.
- Automatically inject the best matching cookie into outgoing requests.
- Persist entries in Burp extension data.

## Matching Rules

Cookie Center normalizes hosts to lowercase and strips trailing dots. For each outgoing request:

1. Disabled entries are ignored.
2. Exact host matches are allowed.
3. Subdomain matches are allowed only when the entry's `Subdomains` checkbox is selected.
4. When more than one entry matches, the most specific host wins.

For example, if both `example.com` and `api.example.com` match `api.example.com`, the `api.example.com` entry is used.

## Build

```bash
./gradlew build
```

The extension jar is generated under `build/libs/`.
