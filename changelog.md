## TIRN Security 1.0.2 alpha

> Release Date: 2026-10-08

- Added legacy Android compatibility support for older Android userspace environments
- Added ARMv7 runtime helper support for 32-bit ARM devices
- Added architecture-specific runtime packages for ARM64 and ARMv7
- Fixed legacy Android policy parsing and rendering compatibility
- Updated policy handling to use full application identity:
  - user
  - package
  - UID
- Improved compatibility with older BusyBox and Android command environments
- Added legacy Android validation on Mecool M8S running Android 9 with Magisk 23.0

## Previous releases

> Release Date: 2026-10-03

## TIRN Security 1.0.1 alpha

- Patch alpha release of TIRN Security 1.0.1
- Fixed fresh-install policy transaction when no previous policy.applied state exists
