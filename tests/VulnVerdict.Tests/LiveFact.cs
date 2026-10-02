namespace VulnVerdict.Tests;

/// <summary>A fact that runs only when VV_LIVE_TESTS is set: it fetches a real vendor endpoint.</summary>
public sealed class LiveFactAttribute : FactAttribute
{
    public LiveFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("VV_LIVE_TESTS")))
            Skip = "Live feed test; set VV_LIVE_TESTS=1 to run against the real endpoint.";
    }
}
