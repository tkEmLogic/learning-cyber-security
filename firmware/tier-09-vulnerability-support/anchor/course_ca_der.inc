/* No trust anchor.
 *
 * ./course build firmware replaces this with the Course certificate authority
 * generated for your Course environment. A build that uses this file produces
 * an image that trusts nothing and refuses every connection, which is the
 * correct failure for a missing anchor.
 */
