# CloudFlare Tools

This Go script processes and filters IPv4 prefixes associated with CloudFlare. It converts these prefixes into `/24` blocks and checks if they belong to the CloudFlare CDN or WARP service.

## Features

- Fetches Cloudflare IPv4 BGP prefixes from bgp.tools.
- Converts filtered prefixes into `/24` blocks.
- Checks prefixes for CloudFlare CDN or WARP services.
- Outputs results to specified files.

## Usage

### Flags

- `-h, --help`: Show help.
- `-f, --fetch`: Fetch and convert to /24 only.
- `-c, --cdn`: Run the CDN checker.
- `-w, --warp`: Run the WARP checker.
- `-o, --output`: Specify the output file name.
