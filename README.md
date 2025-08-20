# BD - NextGen Payload

## Overview
This branch (`nextgen`) contains the new **payload implementation** for OpenBD.  
Unlike the legacy payload (developed in `main`, which was injected directly into the plugin with camouflage), the NextGen payload is designed to be loaded dynamically by a `URLClassLoader` from the loader plugin.

## Why NextGen?
- **Invisible but simpler**  
  The payload remains hidden from plugin scans because it is loaded externally instead of being bundled into the plugin JAR.
- **No obfuscation required**  
  Easier to develop and maintain since the code does not need encryption/obfuscation.
- **Extensible**  
  Straightforward to integrate third-party libraries or custom modules to expand functionality.

## Key Differences
- **`main` branch**: Experimental branch for testing stealth techniques and feature development. Payload code is injected and obfuscated inside the plugin → harder to maintain.  
- **`nextgen` branch**: Clean implementation of the payload as an external JAR, loaded via `URLClassLoader` → easier to extend and integrate with OpenBD.

## Notes
- This branch represents only the **payload code**, not the injector (which is maintained in [OpenBD](https://github.com/tmquan2508/OpenBD)).  
- Obfuscation can still be applied externally if stealth in production is required, but development focus here is simplicity and extensibility.
