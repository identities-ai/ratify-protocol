// Pinned IANA time-zone database for Protocol v2 time_window evaluation
// (SPEC-v2 §5.2). PLACEHOLDER: replaced by the embedded tzdata 2025c loader.

/** The IANA tzdata release this SDK embeds and evaluates against. */
export const TZDB_VERSION_V2 = "2025c";

/** UTC offset in effect at an instant and the exclusive end of that period. */
export interface V2ZoneLookup {
  /** Seconds east of UTC. */
  offset: number;
  /** First UTC second of the next offset period, or null when none follows. */
  end: number | null;
}

/** One zone loaded from the pinned database. */
export interface V2TimeZone {
  readonly name: string;
  lookup(unixSeconds: number): V2ZoneLookup;
}

/** Loads a zone after checking the configured database version. */
export function loadV2TimeZone(configuredVersion: string, tz: string): V2TimeZone {
  if (configuredVersion === "") throw new Error("no tzdb_version is configured");
  if (configuredVersion !== TZDB_VERSION_V2) {
    throw new Error(`configured tzdb_version "${configuredVersion}" differs from the loaded IANA tzdata ${TZDB_VERSION_V2}`);
  }
  throw new Error(`time zone "${tz}" is not in IANA tzdata ${TZDB_VERSION_V2}`);
}
