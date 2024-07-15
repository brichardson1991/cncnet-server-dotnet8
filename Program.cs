using System.CommandLine.Builder;
using System.CommandLine.Hosting;
using System.CommandLine.Parsing;
using CnCNetServer;
using Microsoft.Extensions.DependencyInjection;

return await new CommandLineBuilder(RootCommandBuilder.Build())
    .UseDefaults()
    .UseHost(Host.CreateDefaultBuilder, static hostBuilder =>
        hostBuilder
            .ConfigureServices(static services =>
            {
                services
                    .AddOptions<ServiceOptions>()
                    .BindCommandLine();
                services
                    .AddWindowsService(static o => o.ServiceName = "CnCNetServer")
                    .AddSystemd()
                    .AddHostedService<CnCNetBackgroundService>()
                    .AddSingleton<TunnelV3>()
#if EnableLegacyVersion
                    .AddSingleton<TunnelV2>()
#endif
                    .AddTransient<PeerToPeerUtil>()
                    .AddHttpClient(Options.DefaultName)
                    .ConfigureHttpClient(Startup.ConfigureHttpClient)
                    .UseSocketsHttpHandler(Startup.UseSocketsHttpHandler)
                    .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
            })
            .ConfigureLogging(Startup.ConfigureLogging))
    .Build()
    .InvokeAsync(args)
    .ConfigureAwait(ConfigureAwaitOptions.None);