namespace CnCNetServer;

internal sealed record ServiceOptions
{
    public required int TunnelPort { get; init; }
#if EnableLegacyVersion

    public required int TunnelV2Port { get; init; }
#endif

    public required string Name { get; init; }

    public required int MaxClients { get; init; }

    public required bool NoMasterAnnounce { get; init; }

    public required string? MasterPassword { get; init; }

    public required string? MaintenancePassword { get; init; }

    public required Uri MasterServerUrl { get; init; }

    public required int IpLimit { get; init; }

    public required bool NoPeerToPeer { get; init; }

    public required bool TunnelV3Enabled { get; init; }
#if EnableLegacyVersion

    public required bool TunnelV2Enabled { get; init; }
#endif

    public required LogLevel ServerLogLevel { get; init; }

    public required LogLevel SystemLogLevel { get; init; }

    public required bool AnnounceIpV6 { get; init; }

    public required bool AnnounceIpV4 { get; init; }
#if EnableLegacyVersion

    public required bool TunnelV2Https { get; init; }
#endif

    public required int MaxPacketSize { get; init; }

    public required ushort MaxPingsGlobal { get; init; }

    public required ushort MaxPingsPerIp { get; init; }

    public required ushort MasterAnnounceInterval { get; init; }

    public required int ClientTimeout { get; init; }
}