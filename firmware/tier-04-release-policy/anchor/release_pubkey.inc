/* No release manifest verification key.
 *
 * ./course build firmware replaces this with the public half of the Release
 * signing key generated for your Course environment. A build that uses this
 * file produces an image that can verify no manifest at all, refuses every
 * release, and says which check it could not run.
 *
 * That is the correct failure for a missing key. An image that verified
 * nothing and installed anyway would be Tier 0 wearing Tier 4's console
 * messages.
 */
