# Changelog

## 1.1.0

### Added

- `FRAME_ANCESTORS` option to allow embedding Clear Wicket in a frame from listed origins (`'self'`, `https://host[:port]`). Invalid values stop the server at startup.

### Changed

- Every response now also carries `Content-Security-Policy: frame-ancestors 'none'` next to `X-Frame-Options: DENY`. With `FRAME_ANCESTORS` set, only the CSP `frame-ancestors` directive is sent and `X-Frame-Options` is dropped.

## 1.0.0

Initial release.
