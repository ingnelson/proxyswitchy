using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Web;
using Shadowsocks.Controller;
using System.Text.RegularExpressions;

namespace Shadowsocks.Model
{
    [Serializable]
    public class Server
    {
        public const string DefaultServer = "127.0.0.1";
        public const int DefaultPort = 1090;
        public const string DefaultProxyType = "SOCKS5";

        #region ParseLegacyURL
        public static readonly Regex
            UrlFinder = new Regex(@"ss://(?<base64>[A-Za-z0-9+-/=_]+)(?:#(?<tag>\S+))?", RegexOptions.IgnoreCase),
            DetailsParser = new Regex(@"^((?<method>.+?):(?<password>.*)@(?<hostname>.+?):(?<port>\d+?))$", RegexOptions.IgnoreCase);
        #endregion ParseLegacyURL

        private const int DefaultServerTimeoutSec = 5;
        public const int MaxServerTimeoutSec = 20;

        public string server;
        public int server_port;
        public string proxy_type;
        public string remarks;

        public override int GetHashCode()
        {
            return server.GetHashCode() ^ server_port;
        }

        public override bool Equals(object obj)
        {
            Server o2 = (Server)obj;
            return server == o2.server && server_port == o2.server_port;
        }

        public string FriendlyName()
        {
            if (server.IsNullOrEmpty())
            {
                return I18N.GetString("New server");
            }

            string serverStr = $"{FormatHostName(server)}:{server_port}";
            return remarks.IsNullOrEmpty()
                ? serverStr
                : $"{remarks} ({serverStr})";
        }

        public string FormatHostName(string hostName)
        {
            // CheckHostName() won't do a real DNS lookup
            switch (Uri.CheckHostName(hostName))
            {
                case UriHostNameType.IPv6:  // Add square bracket when IPv6 (RFC3986)
                    return $"[{hostName}]";
                default:    // IPv4 or domain name
                    return hostName;
            }
        }

        public Server()
        {
            server = DefaultServer;
            server_port = DefaultPort;
            proxy_type = DefaultProxyType;
            remarks = "";
        }

        private static Server ParseLegacyURL(string ssURL)
        {
            var match = UrlFinder.Match(ssURL);
            if (!match.Success)
                return null;

            Server server = new Server();
            var base64 = match.Groups["base64"].Value.TrimEnd('/');
            var tag = match.Groups["tag"].Value;
            if (!tag.IsNullOrEmpty())
            {
                server.remarks = HttpUtility.UrlDecode(tag, Encoding.UTF8);
            }
            Match details = null;
            try
            {
                details = DetailsParser.Match(Encoding.UTF8.GetString(Convert.FromBase64String(
                base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='))));
            }
            catch (FormatException)
            {
                return null;
            }
            if (!details.Success)
                return null;
            server.server = details.Groups["hostname"].Value;
            server.server_port = int.Parse(details.Groups["port"].Value);
            return server;
        }

        public string Identifier()
        {
            return server + ':' + server_port;
        }
    }
}
