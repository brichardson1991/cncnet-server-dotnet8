using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace CnCNetServer;

internal static class ExceptionMessageBuilder
{
    public static string GetDetailedExceptionInfo(this Exception ex)
        => new StringBuilder().GetExceptionInfo(ex).ToString();

    public static async ValueTask<string> GetHttpResponseMessageInfoAsync(this HttpResponseMessage httpResponseMessage)
    {
        string content = await httpResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(ConfigureAwaitOptions.None);

        return new StringBuilder()
            .Append(FormattableString.Invariant($"{nameof(HttpResponseMessage)}: {httpResponseMessage}"))
            .AppendLine(FormattableString.Invariant($"{nameof(HttpResponseMessage)}.{nameof(HttpResponseMessage.Content)}: {content}"))
            .ToString();
    }

    private static StringBuilder GetExceptionInfo(this StringBuilder sb, Exception ex)
    {
        sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.GetType)}: {ex.GetType()}"))
            .AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.Message)}: {ex.Message}"))
            .GetExceptionDetails(ex);

        if (ex is AggregateException aggregateException)
        {
            foreach (Exception innerException in aggregateException.InnerExceptions)
            {
                _ = sb.AppendLine(FormattableString.Invariant($"{nameof(AggregateException)}.{nameof(AggregateException.InnerExceptions)}:"))
                    .GetExceptionInfo(innerException);
            }
        }
        else if (ex.InnerException is not null)
        {
            _ = sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.InnerException)}:"))
                .GetExceptionInfo(ex.InnerException);
        }

        return sb;
    }

    private static void GetExceptionDetails(this StringBuilder sb, Exception ex)
        => sb.AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.Source)}: {ex.Source}"))
            .AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.TargetSite)}: {ex.TargetSite}"))
            .GetHttpRequestExceptionDetails(ex)
            .GetHttpIoExceptionDetails(ex)
            .GetSocketExceptionDetails(ex)
            .GetExternalExceptionDetails(ex)
            .AppendLine(FormattableString.Invariant($"{nameof(Exception)}.{nameof(Exception.StackTrace)}: {ex.StackTrace}"));

    private static StringBuilder GetExternalExceptionDetails(this StringBuilder sb, Exception ex)
    {
        if (ex is not ExternalException externalException)
            return sb;

        var win32Exception = new Win32Exception(externalException.ErrorCode);

        return sb.AppendLine(FormattableString.Invariant($"{nameof(ExternalException)}.{nameof(ExternalException.ErrorCode)}: {externalException.ErrorCode}"))
            .AppendLine(FormattableString.Invariant($"{nameof(ExternalException)}.{nameof(ExternalException.ErrorCode)} Hex: 0x{externalException.ErrorCode:X8}"))
            .AppendLine(FormattableString.Invariant($"{nameof(Win32Exception)}.{nameof(Exception.Message)}: {win32Exception.Message}"));
    }

    private static StringBuilder GetSocketExceptionDetails(this StringBuilder sb, Exception ex)
    {
        if (ex is SocketException socketException)
            _ = sb.AppendLine(FormattableString.Invariant($"{nameof(SocketException)}.{nameof(SocketException.SocketErrorCode)}: {socketException.SocketErrorCode}"));

        return sb;
    }

    private static StringBuilder GetHttpRequestExceptionDetails(this StringBuilder sb, Exception ex)
    {
        if (ex is HttpRequestException httpRequestException)
        {
            _ = sb.AppendLine(FormattableString.Invariant($"{nameof(HttpRequestException)}.{nameof(HttpRequestException.HttpRequestError)}: {httpRequestException.HttpRequestError}"))
                .AppendLine(FormattableString.Invariant($"{nameof(HttpRequestException)}.{nameof(HttpRequestException.StatusCode)}: {httpRequestException.StatusCode}"));
        }

        return sb;
    }

    private static StringBuilder GetHttpIoExceptionDetails(this StringBuilder sb, Exception ex)
    {
        if (ex is HttpIOException httpIoException)
            _ = sb.AppendLine(FormattableString.Invariant($"{nameof(HttpIOException)}.{nameof(HttpIOException.HttpRequestError)}: {httpIoException.HttpRequestError}"));

        return sb;
    }
}