# Cookie Center

Cookie Center is a Burp Suite extension for managing request cookies by host.

## Features

- Store one cookie header value per host.
- Enable or disable entries without deleting them.
- Choose whether an entry also applies to subdomains.
- Import host and cookie values from common curl command formats.
- Import cookies directly from Burp's Cookie Jar after browsing or logging in.
- Automatically capture cookie headers from browser traffic passing through Burp Proxy.
- Replace existing entries for the same host instead of creating duplicates.
- Automatically inject the best matching cookie into outgoing requests.
- Persist entries in Burp extension data.

## Getting Cookies

Use one of the following workflows:

1. Open Burp's browser, log in to the target application, then click `Import from Burp Cookie Jar`.
2. Enable `Auto capture from Proxy`, then browse the target through Burp's browser or any browser configured to use Burp Proxy.
3. Paste a curl command with `Import from curl` when you already have a command-line request.

Cookie Jar imports group cookies by domain and convert them into a single request `Cookie` header for each host. Auto capture updates a host entry whenever Proxy traffic contains a new cookie header.

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
