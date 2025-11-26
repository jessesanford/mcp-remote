import { debugLog } from './utils'

/**
 * OAuth 2.0 Authorization Server Metadata as defined in RFC 8414
 * https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
export interface AuthorizationServerMetadata {
  /** The authorization server's issuer identifier */
  issuer: string
  /** URL of the authorization server's authorization endpoint */
  authorization_endpoint?: string
  /** URL of the authorization server's token endpoint */
  token_endpoint?: string
  /** JSON array containing a list of the OAuth 2.0 scope values that this server supports */
  scopes_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 response_type values that this server supports */
  response_types_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 grant type values that this server supports */
  grant_types_supported?: string[]
  /** JSON array containing a list of client authentication methods supported by this token endpoint */
  token_endpoint_auth_methods_supported?: string[]
  /** Additional metadata fields */
  [key: string]: unknown
}

/**
 * OAuth 2.0 Protected Resource Metadata (simplified for our needs)
 * This is used to discover the authorization server for a given resource.
 * Example:
 * {
 *   "resource": "https://example.com/mcp-simple-auth",
 *   "authorization_servers": ["https://auth.example.com/mcpauth"],
 *   ...
 * }
 */
interface ProtectedResourceMetadata {
  resource?: string
  authorization_servers?: string[]
  scopes_supported?: string[]
  [key: string]: unknown
}

/**
 * Constructs the well-known URL for OAuth authorization server metadata
 * @param serverUrl The base server URL
 * @returns The well-known metadata URL
 */
export function getMetadataUrl(serverUrl: string): string {
  const url = new URL(serverUrl)
  // Per RFC 8414, the metadata is at /.well-known/oauth-authorization-server
  // relative to the issuer identifier
  const metadataPath = '/.well-known/oauth-authorization-server'

  // Construct the full metadata URL
  return `${url.origin}${metadataPath}`
}

/**
 * Constructs the well-known URL for OAuth authorization server metadata
 * given an issuer URL, including any path components.
 *
 * Example:
 *   issuer: https://developer-dev.api.autodesk.com/mcpauth
 *   => https://developer-dev.api.autodesk.com/.well-known/oauth-authorization-server/mcpauth
 */
function getMetadataUrlFromIssuer(issuer: string): string {
  const issuerUrl = new URL(issuer)
  const path = issuerUrl.pathname === '/' ? '' : issuerUrl.pathname
  return `${issuerUrl.origin}/.well-known/oauth-authorization-server${path}`
}

/**
 * Constructs the well-known URL for OAuth protected resource metadata
 * based on the MCP server URL.
 *
 * We derive a resource identifier from the first path segment:
 *   https://host/mcp-simple-auth/mcp  ->  /.well-known/oauth-protected-resource/mcp-simple-auth
 */
function getProtectedResourceMetadataUrl(serverUrl: string): string | undefined {
  const url = new URL(serverUrl)
  const segments = url.pathname.split('/').filter(Boolean)
  if (segments.length === 0) {
    return undefined
  }

  const resourceId = segments[0]
  return `${url.origin}/.well-known/oauth-protected-resource/${resourceId}`
}

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoint
 * @param serverUrl The server URL to fetch metadata for
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadata(serverUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  const directMetadataUrl = getMetadataUrl(serverUrl)

  debugLog('Fetching authorization server metadata', { serverUrl, metadataUrl: directMetadataUrl })

  const tryFetch = async (url: string): Promise<AuthorizationServerMetadata | undefined> => {
    try {
      const response = await fetch(url, {
        headers: {
          Accept: 'application/json',
        },
        // Short timeout to avoid blocking
        signal: AbortSignal.timeout(5000),
      })

      if (!response.ok) {
        if (response.status === 404) {
          debugLog('Authorization server metadata endpoint not found (404)', { metadataUrl: url })
        } else {
          debugLog('Failed to fetch authorization server metadata', {
            metadataUrl: url,
            status: response.status,
            statusText: response.statusText,
          })
        }
        return undefined
      }

      const metadata = (await response.json()) as AuthorizationServerMetadata

      debugLog('Successfully fetched authorization server metadata', {
        metadataUrl: url,
        issuer: metadata.issuer,
        scopes_supported: metadata.scopes_supported,
        scopeCount: metadata.scopes_supported?.length || 0,
      })

      return metadata
    } catch (error) {
      debugLog('Error fetching authorization server metadata', {
        error: error instanceof Error ? error.message : String(error),
        metadataUrl: url,
      })
      return undefined
    }
  }

  // 1. Try direct metadata on the MCP server origin
  const directMetadata = await tryFetch(directMetadataUrl)
  if (directMetadata) {
    return directMetadata
  }

  // 2. Fallback: use protected resource metadata to discover the authorization server
  const protectedResourceMetadataUrl = getProtectedResourceMetadataUrl(serverUrl)
  if (!protectedResourceMetadataUrl) {
    return undefined
  }

  debugLog('Attempting protected resource metadata discovery', {
    serverUrl,
    protectedResourceMetadataUrl,
  })

  try {
    const response = await fetch(protectedResourceMetadataUrl, {
      headers: {
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      debugLog('Failed to fetch protected resource metadata', {
        protectedResourceMetadataUrl,
        status: response.status,
        statusText: response.statusText,
      })
      return undefined
    }

    const prMetadata = (await response.json()) as ProtectedResourceMetadata
    const authServers = Array.isArray(prMetadata.authorization_servers) ? prMetadata.authorization_servers : []

    if (!authServers.length) {
      debugLog('Protected resource metadata did not include authorization_servers', {
        protectedResourceMetadataUrl,
        prMetadata,
      })
      return undefined
    }

    // Try each advertised authorization server until one returns valid metadata
    for (const issuer of authServers) {
      try {
        const issuerMetadataUrl = getMetadataUrlFromIssuer(issuer)
        debugLog('Attempting authorization server metadata from issuer', {
          issuer,
          issuerMetadataUrl,
        })

        const issuerMetadata = await tryFetch(issuerMetadataUrl)
        if (issuerMetadata) {
          return issuerMetadata
        }
      } catch (error) {
        debugLog('Error while fetching metadata from issuer', {
          issuer,
          error: error instanceof Error ? error.message : String(error),
        })
      }
    }
  } catch (error) {
    debugLog('Error fetching protected resource metadata', {
      error: error instanceof Error ? error.message : String(error),
      protectedResourceMetadataUrl,
    })
  }

  return undefined
}
