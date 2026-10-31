import {
  encodeRevocationListV2,
  encodeRevocationPushV2,
  newV2StatusPublisherWithKey,
  recordSecurityKeyRoleV2,
  configureStatusKeyEpochV2,
  type V2StatusEvidenceObject,
  type V2StatusPublisher,
  type V2StatusPublisherState,
} from "@identities-ai/ratify-protocol/v2";
import { JournalStoreTestOnly } from "@identities-ai/ratify-protocol/v2/reference";
import type { DemoAuthority } from "./authority.js";

const STATUS_LIFETIME_SECONDS = 3600;

/**
 * The principal's signed revocation status, published under its separate
 * status key by the SDK status publisher. The receiver treats this feed as an
 * untrusted transport: it verifies every object against the status key it
 * pinned out of band, so a feed that lies can make a decision fail closed but
 * cannot make it allow.
 *
 * DEVELOPMENT ONLY: the publisher state lives in memory and the role journal
 * is the SDK's test-only reference store. A real principal persists the
 * returned publisher state before it publishes each signed object.
 */
export class DemoStatusFeed {
  private objects: V2StatusEvidenceObject[] = [];

  private constructor(
    private readonly publisher: V2StatusPublisher,
    private state: V2StatusPublisherState,
  ) {}

  static async create(authority: DemoAuthority, now: number): Promise<DemoStatusFeed> {
    const roles = new JournalStoreTestOnly();
    await recordSecurityKeyRoleV2(roles, "issuer", authority.root.publicKey);
    await recordSecurityKeyRoleV2(roles, "delegation", authority.agent.publicKey);
    await configureStatusKeyEpochV2(roles, authority.rootID, 1, authority.status.publicKey);
    const publisher = await newV2StatusPublisherWithKey(roles, authority.root.publicKey, authority.status, STATUS_LIFETIME_SECONDS);
    const genesis = await publisher.genesis(now);
    const feed = new DemoStatusFeed(publisher, genesis.state);
    feed.objects = [{ objectType: 3, wire: encodeRevocationListV2(genesis.list) }];
    return feed;
  }

  /**
   * The signed objects a receiver fetches: the cumulative list and any later
   * push. A list older than half its lifetime is re-signed first (a heartbeat
   * at the same sequence), so a long-running demo receiver does not go stale.
   */
  async current(now: number): Promise<V2StatusEvidenceObject[]> {
    if (now - this.state.updatedAt >= STATUS_LIFETIME_SECONDS / 2) {
      const published = await this.publisher.heartbeat(this.state, now);
      this.state = published.state;
      this.objects = [{ objectType: 3, wire: encodeRevocationListV2(published.list) }];
    }
    return this.objects.map((o) => ({ objectType: o.objectType, wire: Uint8Array.from(o.wire) }));
  }

  /** Revokes a certificate: a signed push and the cumulative list at the next sequence. */
  async revoke(certID: string, now: number): Promise<void> {
    const published = await this.publisher.revoke(this.state, [certID], now);
    this.state = published.state;
    this.objects = [
      { objectType: 5, wire: encodeRevocationPushV2(published.push!) },
      { objectType: 3, wire: encodeRevocationListV2(published.list) },
    ];
  }
}
