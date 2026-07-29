using System.Collections.Concurrent;

namespace Jakapil.Capture.Replay;

/// <summary>
/// Bounded, thread-safe single-use nonce cache (ADR-0003 §6.6/§7): rejects a <c>(kid, nonce)</c> pair that has
/// already been registered while still within its own expiry — this is what closes the "a captured, still-valid
/// signed header is replayed verbatim against the same or a different request" attack the ADR describes; expiry
/// alone only bounds HOW LONG a captured header stays dangerous, nonce uniqueness is what stops it being reused
/// even once within that window.
/// </summary>
/// <remarks>
/// <b>Bounded by design</b> (ADR-0003 §7's "nonce cache is memory-limited" + PLAN 15d-15 rule 8, no unbounded
/// growth / no DoS vector): capacity is capped at <see cref="ReplayVerificationOptions.NonceCacheSize"/>
/// regardless of how many distinct nonces show up. Once at capacity, registering a new nonce evicts the
/// OLDEST-INSERTED entry to make room, and expired entries are also opportunistically swept on every call so
/// ordinary expiry — not just capacity pressure — reclaims memory over time.
/// <para>
/// <b>Trade-off, stated honestly:</b> capacity-driven eviction can in theory remove an entry before its own
/// <c>exp</c> has passed, in which case that exact nonce could be replayed again before its real deadline. This
/// does not grant anything beyond what a single valid signature already grants (ADR-0003 INV-B2: capture
/// suppression + response masking, never authorization) — it is not a privilege-escalation or
/// plaintext-disclosure vector, only a narrowing of the replay window's effectiveness under sustained high
/// signed-traffic volume. Size <see cref="ReplayVerificationOptions.NonceCacheSize"/> generously relative to
/// (signed requests per second × clock-skew-tolerance window) to make this practically unreachable.
/// </para>
/// <para>
/// Public only because it is a constructor parameter of the publicly-constructed <see cref="ReplayVerifier"/>
/// (the .NET DI container requires public constructors/parameter types) — it is not intended to be used
/// directly by host applications.
/// </para>
/// </remarks>
public sealed class ReplayNonceCache
{
    private readonly int _capacity;
    private readonly ConcurrentDictionary<string, long> _expiryByKey = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string> _insertionOrder = new();

    public ReplayNonceCache(int capacity)
    {
        _capacity = Math.Max(1, capacity);
    }

    /// <summary>
    /// Attempts to register <paramref name="key"/> (the caller uses <c>kid:nonce</c> so nonces are scoped per
    /// signing key) as seen, valid until <paramref name="expiresAtUnixSeconds"/>.
    /// </summary>
    /// <returns>
    /// False (reject — this is a replay) if <paramref name="key"/> is already registered and its recorded
    /// expiry has not yet passed relative to <paramref name="nowUnixSeconds"/>. True (accept, and the key is
    /// now recorded) otherwise — including the first time this exact key is ever seen, and the case where it
    /// was seen before but has since expired.
    /// </returns>
    public bool TryRegister(string key, long expiresAtUnixSeconds, long nowUnixSeconds)
    {
        PurgeExpired(nowUnixSeconds);

        if (_expiryByKey.TryGetValue(key, out var existingExpiry) && existingExpiry > nowUnixSeconds)
        {
            return false;
        }

        _expiryByKey[key] = expiresAtUnixSeconds;
        _insertionOrder.Enqueue(key);

        while (_expiryByKey.Count > _capacity && _insertionOrder.TryDequeue(out var oldest))
        {
            _expiryByKey.TryRemove(oldest, out _);
        }

        return true;
    }

    /// <summary>Evicts a small, bounded number of already-expired entries from the front of the insertion
    /// queue on every call (rather than scanning the whole cache), so this stays O(1)-ish per verification
    /// while still reclaiming memory from ordinary expiry over time, not just capacity pressure.</summary>
    private void PurgeExpired(long nowUnixSeconds)
    {
        var maxSweeps = Math.Min(16, _insertionOrder.Count);
        for (var i = 0; i < maxSweeps; i++)
        {
            if (!_insertionOrder.TryPeek(out var candidate))
            {
                return;
            }

            if (_expiryByKey.TryGetValue(candidate, out var expiry) && expiry > nowUnixSeconds)
            {
                // Front of the queue (oldest inserted) is not expired yet; insertion order roughly tracks
                // expiry order (nonces share a similar expiry window), so stop rather than scan further.
                return;
            }

            _insertionOrder.TryDequeue(out _);
            _expiryByKey.TryRemove(candidate, out _);
        }
    }
}
