﻿namespace CnCNetServer;

using System.Buffers;
using System.Collections.Concurrent;

internal sealed class PeerToPeerUtil : IAsyncDisposable
{
    private const int CounterResetInterval = 60; // Reset counter every X s
    private const int MaxRequestsPerIp = 20; // Max requests during one CounterResetInterval period
    private const int MaxConnectionsGlobal = 5000; // Max amount of different ips sending requests during one CounterResetInterval period
    private const short StunId = 26262;

    private readonly ConcurrentDictionary<int, int> connectionCounter = new();
    private readonly PeriodicTimer connectionCounterTimer = new(TimeSpan.FromSeconds(CounterResetInterval));
    private readonly ILogger logger;

    public PeerToPeerUtil(ILogger<PeerToPeerUtil> logger)
    {
        this.logger = logger;
    }

    public Task StartAsync(int listenPort, CancellationToken cancellationToken)
    {
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
        ResetConnectionCounterAsync(cancellationToken);
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed

        return StartReceiverAsync(listenPort, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        connectionCounterTimer.Dispose();

        return ValueTask.CompletedTask;
    }

    private static bool IsInvalidRemoteIpEndPoint(IPEndPoint remoteEp)
        => remoteEp.Address.Equals(IPAddress.Loopback) || remoteEp.Address.Equals(IPAddress.Any)
        || remoteEp.Address.Equals(IPAddress.Broadcast) || remoteEp.Port == 0;

    private async Task ResetConnectionCounterAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (await connectionCounterTimer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                connectionCounter.Clear();
            }
        }
        catch (OperationCanceledException)
        {
            // ignore, shut down signal
        }
        catch (Exception ex)
        {
            await logger.LogExceptionDetailsAsync(ex).ConfigureAwait(false);
        }
    }

    private async Task StartReceiverAsync(int listenPort, CancellationToken cancellationToken)
    {
        using var client = new Socket(SocketType.Dgram, ProtocolType.Udp);
        var remoteEp = new IPEndPoint(IPAddress.Any, 0);

        client.Bind(new IPEndPoint(IPAddress.IPv6Any, listenPort));

        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInfo(
                FormattableString.Invariant($"{DateTimeOffset.Now} PeerToPeer UDP server started on port {listenPort}."));
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            using IMemoryOwner<byte> memoryOwner = MemoryPool<byte>.Shared.Rent(64);
            Memory<byte> buffer = memoryOwner.Memory[..64];
            SocketReceiveFromResult socketReceiveFromResult;

            try
            {
                socketReceiveFromResult = await client.ReceiveFromAsync(
                    buffer, SocketFlags.None, remoteEp, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                await logger.LogExceptionDetailsAsync(ex).ConfigureAwait(false);
                continue;
            }

            if (socketReceiveFromResult.ReceivedBytes == 48)
            {
#pragma warning disable CS4014
                ReceiveAsync(client, buffer, (IPEndPoint)socketReceiveFromResult.RemoteEndPoint, cancellationToken)
                    .ConfigureAwait(false);
#pragma warning restore CS4014
            }
        }
    }

    private async Task ReceiveAsync(
        Socket client, ReadOnlyMemory<byte> receiveBuffer, IPEndPoint remoteEp, CancellationToken cancellationToken)
    {
        try
        {
            if (logger.IsEnabled(LogLevel.Debug))
                logger.LogDebug(FormattableString.Invariant($"P2P client {remoteEp} connected."));

            if (IsInvalidRemoteIpEndPoint(remoteEp) || IsConnectionLimitReached(remoteEp.Address))
                return;

            if (IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveBuffer.Span)) != StunId)
                return;

            using IMemoryOwner<byte> memoryOwner = MemoryPool<byte>.Shared.Rent(40);
            Memory<byte> sendBuffer = memoryOwner.Memory[..40];

            new Random().NextBytes(sendBuffer.Span);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(StunId)).AsSpan(..2).CopyTo(sendBuffer.Span[6..8]);
            byte[] ipAddressBytes = remoteEp.Address.IsIPv4MappedToIPv6 || remoteEp.AddressFamily is AddressFamily.InterNetwork
                ? remoteEp.Address.MapToIPv4().GetAddressBytes()
                : remoteEp.Address.GetAddressBytes();

            ipAddressBytes.AsSpan(..ipAddressBytes.Length).CopyTo(sendBuffer.Span[..ipAddressBytes.Length]);

            byte[] portBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)remoteEp.Port));

            portBytes.AsSpan(..portBytes.Length).CopyTo(sendBuffer.Span[ipAddressBytes.Length..(ipAddressBytes.Length + 2)]);

            // obfuscate
            for (int i = 0; i < ipAddressBytes.Length + portBytes.Length; i++)
                sendBuffer.Span[i] ^= 0x20;

            await client.SendToAsync(sendBuffer, SocketFlags.None, remoteEp, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // ignore, shut down signal
        }
        catch (Exception ex)
        {
            await logger.LogExceptionDetailsAsync(ex).ConfigureAwait(false);
        }
    }

    private bool IsConnectionLimitReached(IPAddress address)
    {
        if (connectionCounter.Count >= MaxConnectionsGlobal)
            return true;

        int ipHash = address.GetHashCode();

        if (connectionCounter.TryGetValue(ipHash, out int count) && count >= MaxRequestsPerIp)
            return true;

        connectionCounter[ipHash] = ++count;

        return false;
    }
}