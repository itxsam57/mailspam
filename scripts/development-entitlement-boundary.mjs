const DEVELOPMENT_ENTITLEMENT_FLAG = "EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS";

/**
 * Development entitlement is a launcher capability, not project configuration.
 * Apply this only after loading .env.local so stale/local values cannot enable
 * it during the normal consumer-like source journey or disable the dedicated
 * engineering fixture launcher.
 */
export function enforceDevelopmentEntitlementBoundary(environment, dedicatedFixtureLaunch) {
  if (dedicatedFixtureLaunch) {
    environment[DEVELOPMENT_ENTITLEMENT_FLAG] = "1";
    return;
  }
  delete environment[DEVELOPMENT_ENTITLEMENT_FLAG];
}
