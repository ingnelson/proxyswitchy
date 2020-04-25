using Shadowsocks.Encryption;
using Shadowsocks.Model;
using Shadowsocks.Util;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;
using NLog;
using System.Net.NetworkInformation;
using System.Linq;

namespace Shadowsocks.Controller
{
    public class PACServer
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        public const string RESOURCE_NAME = "pac";

        private string PacSecret
        {
            get
            {
                if (string.IsNullOrEmpty(_cachedPacSecret))
                {
                    var rd = new byte[32];
                    RNG.GetBytes(rd);
                    _cachedPacSecret = HttpServerUtility.UrlTokenEncode(rd);
                }
                return _cachedPacSecret;
            }
        }
        private string _cachedPacSecret = "";
        public string PacUrl { get; private set; } = "";

        private Configuration _config;
        private PACDaemon _pacDaemon;

        // Now, pac address and pac port is not controlled by config directly, but the furture is not sure.
        private IPAddress _pacAddress;
        private int _pacPort;
        private Socket _tcpSocket;

        public PACServer(PACDaemon pacDaemon)
        {
            _pacDaemon = pacDaemon;
        }

        public void UpdatePACURL(Configuration config)
        {
            _config = config;
            string usedSecret = _config.secureLocalPac ? $"&secret={PacSecret}" : "";
            string contentHash = GetHash(_pacDaemon.GetPACContent());
            PacUrl = $"http://{config.localHost}:{_pacPort}/{RESOURCE_NAME}?hash={contentHash}{usedSecret}";
            logger.Debug("Set PAC URL:" + PacUrl);
        }

        private static string GetHash(string content)
        {
            return HttpServerUtility.UrlTokenEncode(MbedTLS.MD5(Encoding.ASCII.GetBytes(content)));
        }

        public bool Handle(byte[] firstPacket, int length, Socket socket, object state)
        {
            if (socket.ProtocolType != ProtocolType.Tcp)
            {
                return false;
            }

            try
            {
                /*
                 *  RFC 7230
                 *  
                    GET /hello.txt HTTP/1.1
                    User-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3
                    Host: www.example.com
                    Accept-Language: en, mi 
                 */

                string request = Encoding.UTF8.GetString(firstPacket, 0, length);
                string[] lines = request.Split('\r', '\n');
                bool hostMatch = false, pathMatch = false, useSocks = false;
                bool secretMatch = !_config.secureLocalPac;

                if (lines.Length < 2)   // need at lease RequestLine + Host
                {
                    return false;
                }

                // parse request line
                string requestLine = lines[0];
                // GET /pac?t=yyyyMMddHHmmssfff&secret=foobar HTTP/1.1
                string[] requestItems = requestLine.Split(' ');
                if (requestItems.Length == 3 && requestItems[0] == "GET")
                {
                    int index = requestItems[1].IndexOf('?');
                    if (index < 0)
                    {
                        index = requestItems[1].Length;
                    }
                    string resourceString = requestItems[1].Substring(0, index).Remove(0, 1);
                    if (string.Equals(resourceString, RESOURCE_NAME, StringComparison.OrdinalIgnoreCase))
                    {
                        pathMatch = true;
                        if (!secretMatch)
                        {
                            string queryString = requestItems[1].Substring(index);
                            if (queryString.Contains(PacSecret))
                            {
                                secretMatch = true;
                            }
                        }
                    }
                }

                // parse request header
                for (int i = 1; i < lines.Length; i++)
                {
                    if (string.IsNullOrEmpty(lines[i]))
                        continue;

                    string[] kv = lines[i].Split(new char[] { ':' }, 2);
                    if (kv.Length == 2)
                    {
                        if (kv[0] == "Host")
                        {
                            if (kv[1].Trim() == ((IPEndPoint)socket.LocalEndPoint).ToString())
                            {
                                hostMatch = true;
                            }
                        }
                        //else if (kv[0] == "User-Agent")
                        //{
                        //    // we need to drop connections when changing servers
                        //    if (kv[1].IndexOf("Chrome") >= 0)
                        //    {
                        //        useSocks = true;
                        //    }
                        //}
                    }
                }

                if (hostMatch && pathMatch)
                {
                    if (!secretMatch)
                    {
                        socket.Close(); // Close immediately
                    }
                    else
                    {
                        SendResponse(socket, useSocks);
                    }
                    return true;
                }
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }



        public void SendResponse(Socket socket, bool useSocks)
        {
            try
            {
                IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint;

                string proxy = GetProxyAddress(localEndPoint, useSocks);

                string pacContent = $"var __PROXY__ = '{proxy}';\n" + _pacDaemon.GetPACContent();
                string responseHead =
$@"HTTP/1.1 200 OK
Server: ShadowsocksWindows/{UpdateChecker.Version}
Content-Type: application/x-ns-proxy-autoconfig
Content-Length: { Encoding.UTF8.GetBytes(pacContent).Length}
Connection: Close

";
                byte[] response = Encoding.UTF8.GetBytes(responseHead + pacContent);
                socket.BeginSend(response, 0, response.Length, 0, new AsyncCallback(SendCallback), socket);
                Utils.ReleaseMemory(true);
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
                socket.Close();
            }
        }

        private void SendCallback(IAsyncResult ar)
        {
            Socket conn = (Socket)ar.AsyncState;
            try
            {
                conn.Shutdown(SocketShutdown.Send);
            }
            catch
            { }
        }

        private string GetProxyAddress(IPEndPoint localEndPoint, bool useSocks)
        {
            return localEndPoint.AddressFamily == AddressFamily.InterNetworkV6
                ? $"{(useSocks ? "SOCKS5" : "PROXY")} [{localEndPoint.Address}]:{_config.localPort};"
                : $"{(useSocks ? "SOCKS5" : "PROXY")} {localEndPoint.Address}:{_config.localPort};";
        }

        public void Start(Configuration config)
        {
            _pacPort = GetFreePort(config.isIPv6Enabled);
            if (CheckIfPortInUse(_pacPort))
                throw new Exception(I18N.GetString("Port {0} already in use", _pacPort));

            _pacAddress = config.shareOverLan
                ? (config.isIPv6Enabled ? IPAddress.IPv6Any : IPAddress.Any)
                : (config.isIPv6Enabled ? IPAddress.IPv6Loopback : IPAddress.Loopback);

            //Update pac url before start pac web service.
            UpdatePACURL(config);

            try
            {
                // Create a TCP/IP socket.
                _tcpSocket = new Socket(config.isIPv6Enabled ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _tcpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                IPEndPoint localEndPoint = new IPEndPoint(_pacAddress, _pacPort);

                // Bind the socket to the local endpoint and listen for incoming connections.
                _tcpSocket.Bind(localEndPoint);
                _tcpSocket.Listen(128);

                // Start an asynchronous socket to listen for connections.
                _tcpSocket.BeginAccept(new AsyncCallback(AcceptCallback), _tcpSocket);
            }
            catch (SocketException)
            {
                _tcpSocket.Close();
                throw;
            }
        }

        private void AcceptCallback(IAsyncResult ar)
        {
            Socket listener = (Socket)ar.AsyncState;
            try
            {
                Socket conn = listener.EndAccept(ar);

                byte[] buf = new byte[4096];
                object[] state = new object[] {
                    conn,
                    buf
                };

                conn.BeginReceive(buf, 0, buf.Length, 0,
                    new AsyncCallback(ReceiveCallback), state);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
            }
            finally
            {
                try
                {
                    listener.BeginAccept(
                        new AsyncCallback(AcceptCallback),
                        listener);
                }
                catch (ObjectDisposedException)
                {
                    // do nothing
                }
                catch (Exception e)
                {
                    logger.LogUsefulException(e);
                }
            }
        }

        private void ReceiveCallback(IAsyncResult ar)
        {
            object[] state = (object[])ar.AsyncState;

            Socket conn = (Socket)state[0];
            byte[] buf = (byte[])state[1];
            try
            {
                int bytesRead = conn.EndReceive(ar);
                if (bytesRead <= 0) goto Shutdown;
                Handle(buf, bytesRead, conn, null);
                Shutdown:
                // no service found for this
                if (conn.ProtocolType == ProtocolType.Tcp)
                {
                    conn.Close();
                }
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
                conn.Close();
            }
        }

        private bool CheckIfPortInUse(int port)
        {
            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            return ipProperties.GetActiveTcpListeners().Any(endPoint => endPoint.Port == port);
        }

        public void Stop()
        {
            if (_tcpSocket != null)
            {
                _tcpSocket.Close();
                _tcpSocket = null;
            }
        }

        private int GetFreePort(bool isIPv6 = false)
        {
            int defaultPort = 8123;
            try
            {
                // TCP stack please do me a favor
                TcpListener l = new TcpListener(isIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0);
                l.Start();
                var port = ((IPEndPoint)l.LocalEndpoint).Port;
                l.Stop();
                return port;
            }
            catch (Exception e)
            {
                // in case access denied
                logger.LogUsefulException(e);
                return defaultPort;
            }
        }
    }
}
