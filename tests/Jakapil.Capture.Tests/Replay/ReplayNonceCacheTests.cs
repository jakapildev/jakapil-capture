using Jakapil.Capture.Replay;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>ADR-0003 §6.6/§7 + PLAN 15d-15 rule 8: the nonce cache rejects a replayed nonce and is bounded
/// (never grows without limit).</summary>
public class ReplayNonceCacheTests
{
    [Fact]
    public void TryRegister_FirstUseOfNonce_Accepted()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        Assert.True(cache.TryRegister("kid:nonce1", expiresAtUnixSeconds: 1000, nowUnixSeconds: 500));
    }

    [Fact]
    public void TryRegister_SameNonceTwiceWithinExpiry_SecondCallRejected_ReplayDetected()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        Assert.True(cache.TryRegister("kid:nonce1", expiresAtUnixSeconds: 1000, nowUnixSeconds: 500));
        Assert.False(cache.TryRegister("kid:nonce1", expiresAtUnixSeconds: 1000, nowUnixSeconds: 501));
    }

    [Fact]
    public void TryRegister_SameNonceAfterItsOwnExpiry_Accepted()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        Assert.True(cache.TryRegister("kid:nonce1", expiresAtUnixSeconds: 1000, nowUnixSeconds: 500));
        // now (1001) is past the recorded expiry (1000): this is a fresh registration, not a replay.
        Assert.True(cache.TryRegister("kid:nonce1", expiresAtUnixSeconds: 2000, nowUnixSeconds: 1001));
    }

    [Fact]
    public void TryRegister_DifferentNonces_BothAccepted_Independent()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        Assert.True(cache.TryRegister("kid:nonceA", 1000, 500));
        Assert.True(cache.TryRegister("kid:nonceB", 1000, 500));
    }

    [Fact]
    public void TryRegister_NoncesScopedByKeyId_SameNonceStringDifferentKid_BothAccepted()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        Assert.True(cache.TryRegister("kidA:sameNonce", 1000, 500));
        Assert.True(cache.TryRegister("kidB:sameNonce", 1000, 500));
    }

    [Fact]
    public void TryRegister_Bounded_CapacityNeverExceeded_EvenUnderHighVolume()
    {
        var cache = new ReplayNonceCache(capacity: 50);

        for (var i = 0; i < 5000; i++)
        {
            cache.TryRegister($"kid:nonce{i}", expiresAtUnixSeconds: 100_000, nowUnixSeconds: 1);
        }

        // The cache must never grow past its configured capacity, regardless of how many distinct nonces are
        // registered — this is the DoS-bounding guarantee (PLAN 15d-15 rule 8). We assert this indirectly: an
        // early nonce must eventually have been evicted (capacity-bounded), proven by it being re-acceptable
        // even though it is still, notionally, "within its expiry" — capacity eviction beat expiry here.
        Assert.True(cache.TryRegister("kid:nonce0", expiresAtUnixSeconds: 100_000, nowUnixSeconds: 1));
    }

    [Fact]
    public void TryRegister_JustRegisteredNonce_IsRejectedIfReplayedImmediately_EvenNearCapacity()
    {
        var cache = new ReplayNonceCache(capacity: 10);

        for (var i = 0; i < 5; i++)
        {
            cache.TryRegister($"kid:old{i}", expiresAtUnixSeconds: 100_000, nowUnixSeconds: 1);
        }

        Assert.True(cache.TryRegister("kid:recent", expiresAtUnixSeconds: 100_000, nowUnixSeconds: 1));
        // Immediately replaying the just-registered nonce is rejected — capacity is nowhere near exceeded yet.
        Assert.False(cache.TryRegister("kid:recent", expiresAtUnixSeconds: 100_000, nowUnixSeconds: 1));
    }
}
