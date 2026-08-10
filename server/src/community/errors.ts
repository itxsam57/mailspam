export class CommunityReportValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CommunityReportValidationError";
  }
}

export class CommunityReportRateLimitError extends Error {
  constructor() {
    super("Community reporting rate limit reached.");
    this.name = "CommunityReportRateLimitError";
  }
}

export class CommunityReportCapacityError extends Error {
  constructor() {
    super("Community reporting store capacity reached.");
    this.name = "CommunityReportCapacityError";
  }
}

export class CommunityServiceDisabledError extends Error {
  constructor() {
    super("Community aggregation service is disabled.");
    this.name = "CommunityServiceDisabledError";
  }
}
