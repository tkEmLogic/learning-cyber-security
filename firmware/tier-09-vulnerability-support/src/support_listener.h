/*
 * The support listener, Tier 9's planted flaw. Settled on #269; it is
 * T9-W-34 in the Weakness ledger.
 *
 * The release at security counter 5 added it so a support engineer on the
 * customer's network could take a fleet inventory without the update service.
 * It listens on UDP and understands two requests, each a single line:
 *
 *   inventory   answered with the device id, the running release and the
 *               security counter, the same facts a status event carries;
 *   reboot      answered, then the chip is reset.
 *
 * Neither is authenticated. Anything that can send a datagram to the board
 * can take the inventory and can restart the device, and nothing on the device
 * or in the service records who asked. That is the flaw, and the course never
 * repairs it: the remediation release at counter 6 compiles this file out.
 *
 * It is a separate thread with its own socket, because main owns the one
 * outbound exchange (#158) and a listener must be able to answer while main
 * is blocked in a poll. It does not feed the watchdog. It vouches for nothing.
 */

#ifndef COURSE_SUPPORT_LISTENER_H
#define COURSE_SUPPORT_LISTENER_H

/*
 * Start the listener once the network has an address. reset is main.c's
 * whole-chip reset, the same one an installed update uses, because
 * sys_reboot() alone leaves MCUboot hung in its clock setup.
 */
void course_support_listener_start(void (*reset)(void));

#endif /* COURSE_SUPPORT_LISTENER_H */
