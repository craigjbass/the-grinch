# The Grinch

Mostly vibe coded, with a bit of engineering help, static config builder for Santa, intended for small or experimental deployments.

Import the santa.mobileconfig file into your device profiles, and run Santa locally.

## Monitoring 

Inspect what's going on with

```bash
log stream --predicate 'process == "com.northpolesec.santa.daemon"'
```