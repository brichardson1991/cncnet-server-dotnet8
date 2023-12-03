namespace CnCNetServer;

internal sealed class TunnelClient
{
    private readonly int timeout;

    private long lastReceiveTick;

    private SocketAddress? remoteSocketAddress;

    public TunnelClient(int timeout, SocketAddress? remoteSocketAddress = null)
    {
        this.timeout = timeout;
        RemoteSocketAddress = remoteSocketAddress;

        SetLastReceiveTick();
    }

    public SocketAddress? RemoteSocketAddress
    {
        get => remoteSocketAddress;

        set
        {
            remoteSocketAddress = value;
            RemoteIpEndPoint = remoteSocketAddress is not null ? (IPEndPoint)new IPEndPoint(0, 0).Create(remoteSocketAddress) : null;
        }
    }

    public IPEndPoint? RemoteIpEndPoint { get; private set; }

    public bool TimedOut => TimeSpan.FromTicks(DateTime.UtcNow.Ticks - lastReceiveTick).TotalSeconds >= timeout;

    public void SetLastReceiveTick() => lastReceiveTick = DateTime.UtcNow.Ticks;
}