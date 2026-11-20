// Refusals of the Verify MCP signer (Preview). Messages never carry key
// material, proofs, or tool arguments.

/** Base class of every refusal the MCP signer raises. Preview. */
export class McpSignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The tool or its arguments are outside the restricted value model; nothing is signed. Preview. */
export class InvalidArgumentsError extends McpSignerError {
  constructor(message = "mcp: invalid tool arguments") {
    super(message);
  }
}

/** The console client configuration is missing a field or has a field of the wrong form. Preview. */
export class InvalidConfigError extends McpSignerError {
  constructor(message = "mcp: invalid client configuration") {
    super(message);
  }
}

/** The challenge does not match the pinned configuration or the call, or expires too soon. Preview. */
export class ChallengeRefusedError extends McpSignerError {
  constructor(message = "mcp: challenge refused") {
    super(message);
  }
}

/** The text is not a well-formed connect token from the console. Preview. */
export class InvalidConnectTokenError extends McpSignerError {
  constructor(message = "mcp: not a ratify-mcp-connect-1 token from the console") {
    super(message);
  }
}
