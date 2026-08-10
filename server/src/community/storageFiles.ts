export const COMMUNITY_REPORT_KEY_FILE = "community-storage.key";
export const COMMUNITY_REPORT_DATABASE_FILE = "community-reports.enc.json";
export const COMMUNITY_SIGNING_PRIVATE_FILE = "community-feed-private.pem";
export const COMMUNITY_SIGNING_PUBLIC_FILE = "community-feed-public.pem";
export const COMMUNITY_SIGNING_ACTIVE_MANIFEST_FILE = "community-feed-active-key.json";
export const COMMUNITY_SIGNING_NEXT_MANIFEST_FILE = "community-feed-next-key.json";
export const COMMUNITY_FEED_CACHE_FILE = "community-feed-cache.json";

export const COMMUNITY_VERSIONED_PRIVATE_KEY_RE = /^community-feed-key-([a-f0-9]{24})\.private\.pem$/;
export const COMMUNITY_VERSIONED_PUBLIC_KEY_RE = /^community-feed-key-([a-f0-9]{24})\.public\.pem$/;

export const COMMUNITY_AUTHORITATIVE_BASE_FILES = Object.freeze([
  COMMUNITY_REPORT_KEY_FILE,
  COMMUNITY_REPORT_DATABASE_FILE,
  COMMUNITY_SIGNING_PRIVATE_FILE,
  COMMUNITY_SIGNING_PUBLIC_FILE,
  COMMUNITY_SIGNING_ACTIVE_MANIFEST_FILE,
]);
