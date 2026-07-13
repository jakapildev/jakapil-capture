# Jakapil.Capture

**Jakapil Capture** is an ASP.NET Core middleware SDK that captures HTTP traffic from running
.NET APIs. You add it to your application as a single line of middleware; it captures incoming
requests, outgoing responses, and correlation signals in the background — without blocking the
request path — and exports them to a Jakapil collector.

The captured traffic is turned into self-verifying test scenarios on the Jakapil side. The
middleware is designed to be safe under production load: the response always streams to the client
without buffering, the capture copy is bounded, and the queue drops the oldest entries under
backpressure (it never blocks the request pipeline).

## Installation

```bash
dotnet add package Jakapil.Capture
```

## Usage

Register the service and add the middleware to the pipeline in `Program.cs`:

```csharp
builder.Services.AddJakapilCapture(
    ingestKey: builder.Configuration["Jakapil:Capture:IngestKey"]!,
    collectorUri: "https://collector.jakapil.example");

// ...

app.UseJakapilCapture();
```

`ingestKey` is your ingest key and is sent to the collector verbatim in the `X-Jakapil-Key`
header — so it must be supplied **only through an environment variable / secret** and never
hard-coded. `collectorUri` is the collector address where captured interactions are sent.

If you need finer control, you can use the overload that takes an `Action<JakapilCaptureOptions>`:

```csharp
builder.Services.AddJakapilCapture(options =>
{
    options.IngestKey = builder.Configuration["Jakapil:Capture:IngestKey"]!;
    options.CollectorUri = "https://collector.jakapil.example";
    options.SampleRate = 0.25;
});
```

## Configuration options

| Option | Type | Default | Description |
|---|---|---|---|
| `Enabled` | `bool` | `true` | Main on/off switch. When `false`, the middleware is a pure passthrough. |
| `SampleRate` | `double` | `1.0` | The fraction of requests to capture, `[0, 1]`. `1.0` = capture everything. |
| `CollectorUri` | `string?` | `null` | The root address of the collector where captured interactions are sent. If left empty, the export worker stays idle. |
| `IngestKey` | `string?` | `null` | The raw ingest key sent to the collector in the `X-Jakapil-Key` header. |
| `MaxInlineBodyBytes` | `int` | `1048576` (1 MiB) | Bodies at or below this size are captured inline; larger ones are truncated and flagged as `Truncated`. |

Other settings (`MaxCapturedResponseBytes`, `StreamingContentTypes`, `QueueCapacity`,
`SensitiveHeaderNames`, `CorrelationHeaderNames`, `ExportBatchMaxItems`,
`ExportFlushIntervalSeconds`) ship with sensible defaults; see the `JakapilCaptureOptions`
XML documentation comments for details.

## License

MIT
