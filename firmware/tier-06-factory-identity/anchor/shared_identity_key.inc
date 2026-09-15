/* No shared development identity key.
 *
 * ./course build firmware --tier 06 --variant shared replaces this with the
 * private half of the fleet identity generated for your Course environment.
 * A build that uses this file produces a shared image that cannot prove
 * possession of anything and says so, which is the correct failure for a
 * missing credential.
 *
 * This is the one file in the course whose generated form holds a private key.
 * It is written into generated state, never into the repository.
 */
