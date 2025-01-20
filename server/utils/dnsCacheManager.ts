import logger from '@server/logger';
import { LRUCache } from 'lru-cache';
import type { RecordWithTtl } from 'node:dns';
import dns from 'node:dns';
import net from 'node:net';

interface DnsCache {
  address: string;
  family: number;
  timestamp: number;
  ttl: number;
}

interface CacheStats {
  hits: number;
  misses: number;
}

interface ConnectionResult {
  address: string;
  family: number;
  duration: number;
  success: boolean;
}

class DnsCacheManager {
  private cache: LRUCache<string, DnsCache>;
  private lookupAsync: typeof dns.promises.lookup;
  private resolver: dns.promises.Resolver;
  private connectionCache: Map<
    string,
    {
      preferredFamily: number;
      lastSuccess: number;
    }
  >;
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
  };
  private hardTtlMs: number;
  private readonly IPV_DELAY = 50;
  private readonly CONNECTION_TIMEOUT = 2000;

  constructor(maxSize = 500, hardTtlMs = 300000) {
    this.cache = new LRUCache<string, DnsCache>({
      max: maxSize,
      ttl: hardTtlMs,
    });
    this.hardTtlMs = hardTtlMs;
    this.lookupAsync = dns.promises.lookup;
    this.resolver = new dns.promises.Resolver();
    this.connectionCache = new Map();
  }

  private async attemptConnection(
    address: string,
    port: number,
    family: number
  ): Promise<ConnectionResult> {
    const startTime = Date.now();

    return new Promise((resolve) => {
      const socket = new net.Socket();

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({
          address,
          family,
          duration: Date.now() - startTime,
          success: false,
        });
      }, this.CONNECTION_TIMEOUT);

      socket.once('error', () => {
        clearTimeout(timeoutId);
        socket.destroy();
        resolve({
          address,
          family,
          duration: Date.now() - startTime,
          success: false,
        });
      });

      socket.connect(port, address, () => {
        clearTimeout(timeoutId);
        socket.destroy();
        resolve({
          address,
          family,
          duration: Date.now() - startTime,
          success: true,
        });
      });
    });
  }

  private async resolveAddresses(hostname: string): Promise<{
    ipv4Records: RecordWithTtl[];
    ipv6Records: RecordWithTtl[];
  }> {
    const [ipv4Result, ipv6Result] = await Promise.allSettled([
      this.resolver.resolve4(hostname, { ttl: true }),
      this.resolver.resolve6(hostname, { ttl: true }),
    ]);

    return {
      ipv4Records: ipv4Result.status === 'fulfilled' ? ipv4Result.value : [],
      ipv6Records: ipv6Result.status === 'fulfilled' ? ipv6Result.value : [],
    };
  }

  private sortAddresses(
    hostname: string,
    ipv4Records: RecordWithTtl[],
    ipv6Records: RecordWithTtl[]
  ): { ipv4Sorted: RecordWithTtl[]; ipv6Sorted: RecordWithTtl[] } {
    const cached = this.connectionCache.get(hostname);

    if (cached) {
      const sortBySuccess = (a: RecordWithTtl, b: RecordWithTtl) => {
        const aSuccess = this.connectionCache.get(a.address)?.lastSuccess || 0;
        const bSuccess = this.connectionCache.get(b.address)?.lastSuccess || 0;
        return bSuccess - aSuccess;
      };

      if (cached.preferredFamily === 6) {
        ipv6Records.sort(sortBySuccess);
      } else {
        ipv4Records.sort(sortBySuccess);
      }
    }

    return {
      ipv4Sorted: ipv4Records,
      ipv6Sorted: ipv6Records,
    };
  }

  private async resolveWithTtl(
    hostname: string,
    port = 443
  ): Promise<{ address: string; family: number; ttl: number }> {
    if (!this.resolver) {
      throw new Error('Resolver is not initialized');
    }

    try {
      const { ipv4Records, ipv6Records } = await this.resolveAddresses(
        hostname
      );

      if (!ipv4Records.length && !ipv6Records.length) {
        throw new Error(`No DNS records found for ${hostname}`);
      }

      const { ipv4Sorted, ipv6Sorted } = this.sortAddresses(
        hostname,
        ipv4Records,
        ipv6Records
      );

      let ipv6Promise: Promise<ConnectionResult> | null = null;
      if (ipv6Sorted.length) {
        ipv6Promise = this.attemptConnection(ipv6Sorted[0].address, port, 6);
      }

      await new Promise((resolve) => setTimeout(resolve, this.IPV_DELAY));

      let ipv4Promise: Promise<ConnectionResult> | null = null;
      if (ipv4Sorted.length) {
        ipv4Promise = this.attemptConnection(ipv4Sorted[0].address, port, 4);
      }

      const attempts: Promise<ConnectionResult>[] = [];
      if (ipv6Promise) {
        attempts.push(ipv6Promise);
      }
      if (ipv4Promise) {
        attempts.push(ipv4Promise);
      }

      const result = await Promise.race(attempts);

      if (!result.success) {
        this.connectionCache.set(hostname, {
          preferredFamily: result.family,
          lastSuccess: Date.now(),
        });
        this.connectionCache.set(result.address, {
          preferredFamily: result.family,
          lastSuccess: Date.now(),
        });
      }

      const record =
        result.family === 6
          ? ipv6Sorted.find((r) => r.address === result.address)
          : ipv4Sorted.find((r) => r.address === result.address);

      // const ttl = record.ttl > 0 ? record.ttl * 1000 : 30000;
      const ttl = record && record.ttl > 0 ? record.ttl * 1000 : 30000;
      logger.debug(
        `Resolved ${hostname} with TTL: ${record?.ttl} (Original), ${ttl} (Applied)`,
        {
          label: 'DNSCache',
          address: result.address,
          family: result.family,
          duration: result.duration,
        }
      );

      return { address: result.address, family: result.family, ttl };
    } catch (error) {
      logger.error(`Failed to resolve ${hostname} with TTL: ${error.message}`, {
        label: 'DNSCache',
      });
      throw error;
    }
  }

  async lookup(hostname: string): Promise<DnsCache> {
    // Ignore for localhost
    if (hostname === 'localhost') {
      return {
        address: '127.0.0.1',
        family: 4,
        timestamp: Date.now(),
        ttl: 0,
      };
    }

    const cached = this.cache.get(hostname);
    if (cached) {
      const age = Date.now() - cached.timestamp;
      const ttlRemaining = Math.max(0, cached.ttl - age);

      if (ttlRemaining > 0) {
        this.stats.hits++;
        logger.debug(`DNS cache hit for ${hostname}`, {
          label: 'DNSCache',
          address: cached.address,
          family: cached.family,
          age,
          ttlRemaining,
        });
        return cached;
      }

      // soft expiration using stale entry while refreshing
      if (age < this.hardTtlMs) {
        this.stats.hits++;
        logger.debug(`Using stale DNS cache for ${hostname}`, {
          label: 'DNSCache',
          address: cached.address,
          family: cached.family,
          age,
          ttlRemaining,
        });

        // revalidation
        this.resolveWithTtl(hostname)
          .then((result) => {
            this.cache.set(hostname, {
              address: result.address,
              family: result.family,
              timestamp: Date.now(),
              ttl: result.ttl,
            });
            logger.debug(`DNS cache refreshed for ${hostname}`, {
              label: 'DNSCache',
              address: result.address,
              family: result.family,
              ttl: result.ttl,
            });
          })
          .catch((error) => {
            logger.error(
              `Failed to refresh DNS for ${hostname}: ${error.message}`
            );
          });

        return cached;
      }

      // hard expiration: remove stale entry
      this.cache.delete(hostname);
    }

    this.stats.misses++;
    try {
      const result = await this.resolveWithTtl(hostname);

      const dnsCache: DnsCache = {
        address: result.address,
        family: result.family,
        timestamp: Date.now(),
        ttl: result.ttl,
      };

      this.cache.set(hostname, dnsCache, { ttl: this.hardTtlMs });
      logger.debug(`DNS cache miss for ${hostname}, cached new result`, {
        label: 'DNSCache',
        address: dnsCache.address,
        family: dnsCache.family,
        ttl: result.ttl,
      });

      return dnsCache;
    } catch (error) {
      throw new Error(`DNS lookup failed for ${hostname}: ${error.message}`);
    }
  }

  getStats() {
    const entries = [...this.cache.entries()];
    return {
      size: entries.length,
      maxSize: this.cache.max,
      hits: this.stats.hits,
      misses: this.stats.misses,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses || 1),
    };
  }

  getCacheEntries() {
    const entries: Record<
      string,
      {
        address: string;
        family: number;
        age: number;
        ttl: number;
      }
    > = {};

    for (const [hostname, data] of this.cache.entries()) {
      const age = Date.now() - data.timestamp;
      const ttl = Math.max(0, data.ttl - age);

      entries[hostname] = {
        address: data.address,
        family: data.family,
        age,
        ttl,
      };
    }

    return entries;
  }

  getCacheEntry(hostname: string) {
    const entry = this.cache.get(hostname);
    if (!entry) {
      return null;
    }

    return {
      address: entry.address,
      family: entry.family,
      age: Date.now() - entry.timestamp,
      ttl: (this.cache.ttl ?? 300000) - (Date.now() - entry.timestamp),
    };
  }

  clear() {
    this.cache.clear();
    this.connectionCache.clear();
    this.stats.hits = 0;
    this.stats.misses = 0;
    logger.debug('DNS cache cleared', { label: 'DNSCache' });
  }
}

export const dnsCache = new DnsCacheManager();
