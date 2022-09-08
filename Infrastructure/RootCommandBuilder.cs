﻿namespace CnCNetServer;

using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.CommandLine.Parsing;

internal static class RootCommandBuilder
{
    public static RootCommand Build()
    {
        var nameOption = new Option<string>("--name", "Name of the server") { IsRequired = true };
        var maxClientsOption = new Option<int>("--maxclients", () => 200, "Maximum clients allowed on the tunnel server");
        var ipLimitOption = new Option<int>("--iplimit", () => 8, "Maximum clients allowed per IP address");
        var tunnelPortOption = new Option<int>(new[] { "--tunnelport", "--port" }, () => 50001, "Port used for the V3 tunnel server");
        var tunnelV2PortOption = new Option<int>(new[] { "--tunnelv2port", "--portv2" }, () => 50000, "Port used for the V2 tunnel server");

        nameOption.AddValidator(result =>
        {
            if (result.GetValueOrDefault<string>()!.Any(q => q == ';'))
                result.ErrorMessage = $"{nameof(ServiceOptions.Name)} cannot contain the character ;";
        });
        maxClientsOption.AddValidator(result =>
        {
            const int minMaxClients = 2;

            if (result.GetValueOrDefault<int>() < minMaxClients)
                result.ErrorMessage = $"{nameof(ServiceOptions.MaxClients)} minimum is {minMaxClients}";
        });
        ipLimitOption.AddValidator(result =>
        {
            const int minIpLimit = 1;

            if (result.GetValueOrDefault<int>() < minIpLimit)
                result.ErrorMessage = $"{nameof(ServiceOptions.IpLimit)} minimum is {minIpLimit}";
        });
        tunnelPortOption.AddValidator(ValidatePort);
        tunnelV2PortOption.AddValidator(ValidatePort);

        var rootCommand = new RootCommand("CnCNet tunnel server")
        {
            nameOption,
            tunnelPortOption,
            tunnelV2PortOption,
            maxClientsOption,
            new Option<bool>(new[] { "--nomasterannounce", "--nomaster" }, () => false, "Don't register to master"),
            new Option<string?>(new[] { "--masterpassword", "--masterpw" }, () => null, "Master password"),
            new Option<string?>(new[] { "--maintenancepassword", "--maintpw" }, () => null, "Maintenance password"),
            new Option<Uri>(new[] { "--masterserverurl", "--master" }, () => new("https://cncnet.org/master-announce"), "Master server URL"),
            ipLimitOption,
            new Option<bool>(new[] { "--nopeertopeer", "--nop2p" }, () => false, "Disable NAT traversal ports (8054, 3478 UDP)"),
            new Option<bool>(new[] { "--tunnelv3enabled", "--tunnelv3" }, () => true, "Start a V3 tunnel server"),
            new Option<bool>(new[] { "--tunnelv2enabled", "--tunnelv2" }, () => true, "Start a V2 tunnel server"),
            new Option<LogLevel>("--serverloglevel", () => LogLevel.Information, "CnCNet server messages log level"),
            new Option<LogLevel>("--systemloglevel", () => LogLevel.Warning, "Low level system messages log level"),
            new Option<bool>("--forceipv4Announce", () => true, "Force announce using IPv4 address to master server")
        };

        rootCommand.Handler = CommandHandler.Create<IHost>(host => host.WaitForShutdownAsync());

        return rootCommand;
    }

    private static void ValidatePort(OptionResult result)
    {
        const int minPort = 1024;
        const int maxPort = 65534;

        if (result.GetValueOrDefault<int>() is < minPort or > maxPort)
            result.ErrorMessage = $"{nameof(ServiceOptions.TunnelPort)} minimum is {minPort} and maximum is {maxPort}";
    }
}