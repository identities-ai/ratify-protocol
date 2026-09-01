# Guarded actuator adapter

This is the only module permitted to invoke the demo actuator. Its entry point
must require a verifier-produced allow result and must have no independent
request or network path. The first implementation will use an LED, buzzer, or
software simulator; any GPIO wiring remains non-hazardous.
