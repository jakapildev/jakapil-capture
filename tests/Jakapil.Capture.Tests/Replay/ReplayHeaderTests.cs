using Jakapil.Capture.Replay;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>ADR-0003 §6.3: <c>X-Jakapil-Replay</c> header parsing. Parsing only checks shape (all eleven
/// fields present, no unknown fields) — it proves nothing about authenticity.</summary>
public class ReplayHeaderTests
{
    private const string ValidHeader =
        "v=1;alg=ES256;kid=AbCdEfGh;tid=t1;eid=e1;rid=r1;req=q1;ts=1700000000;exp=1700000300;n=nonce123;sig=c2ln";

    [Fact]
    public void TryParse_WellFormedHeader_ParsesAllElevenFields()
    {
        var header = ReplayHeader.TryParse(ValidHeader);

        Assert.NotNull(header);
        Assert.Equal("1", header!.Version);
        Assert.Equal("ES256", header.Alg);
        Assert.Equal("AbCdEfGh", header.KeyId);
        Assert.Equal("t1", header.TenantId);
        Assert.Equal("e1", header.EnvironmentId);
        Assert.Equal("r1", header.RunId);
        Assert.Equal("q1", header.RequestId);
        Assert.Equal("1700000000", header.Timestamp);
        Assert.Equal("1700000300", header.Expiry);
        Assert.Equal("nonce123", header.Nonce);
        Assert.Equal("c2ln", header.Signature);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryParse_EmptyOrNullValue_ReturnsNull(string? value)
    {
        Assert.Null(ReplayHeader.TryParse(value));
    }

    [Fact]
    public void TryParse_MissingRequiredField_ReturnsNull()
    {
        var missingSig = "v=1;alg=ES256;kid=AbCdEfGh;tid=t1;eid=e1;rid=r1;req=q1;ts=1700000000;exp=1700000300;n=nonce123";

        Assert.Null(ReplayHeader.TryParse(missingSig));
    }

    [Fact]
    public void TryParse_UnknownField_ReturnsNull_FailsClosed()
    {
        var withUnknownField = ValidHeader + ";unknown=value";

        Assert.Null(ReplayHeader.TryParse(withUnknownField));
    }

    [Theory]
    [InlineData("novalue;alg=ES256")]
    [InlineData("=novalue;alg=ES256")]
    [InlineData("v=1;alg=ES256;kid=;tid=t1;eid=e1;rid=r1;req=q1;ts=1;exp=2;n=n;sig=s")]
    public void TryParse_MalformedKeyValuePair_ReturnsNull(string malformed)
    {
        Assert.Null(ReplayHeader.TryParse(malformed));
    }

    [Fact]
    public void TryParse_FieldOrderInWireDoesNotMatter_StillParsesCorrectly()
    {
        // Grammar order in the ADR is fixed, but the parser is lenient about order for robustness — the
        // CANONICAL STRING builder is what enforces the binding order, not this parser.
        var reordered = "sig=c2ln;n=nonce123;exp=1700000300;ts=1700000000;req=q1;rid=r1;eid=e1;tid=t1;kid=AbCdEfGh;alg=ES256;v=1";

        var header = ReplayHeader.TryParse(reordered);

        Assert.NotNull(header);
        Assert.Equal("ES256", header!.Alg);
        Assert.Equal("c2ln", header.Signature);
    }
}
