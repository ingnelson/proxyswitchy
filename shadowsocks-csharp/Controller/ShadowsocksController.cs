using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Forms;
using NLog;
using Shadowsocks.Model;
using Shadowsocks.Util;

namespace Shadowsocks.Controller
{
    public class ShadowsocksController
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        // controller:
        // handle user actions
        // manipulates UI
        // interacts with low level logic

        private Thread _ramThread;
        private PACDaemon _pacDaemon;
        private PACServer _pacServer;
        private Configuration _config;
        private PrivoxyRunner privoxyRunner;
        private GFWListUpdater gfwListUpdater;

        public StatisticsStrategyConfiguration StatisticsConfiguration { get; private set; }

        private long _inboundCounter = 0;
        private long _outboundCounter = 0;
        public long InboundCounter => Interlocked.Read(ref _inboundCounter);
        public long OutboundCounter => Interlocked.Read(ref _outboundCounter);

        private bool stopped = false;

        public class PathEventArgs : EventArgs
        {
            public string Path;
        }

        public class UpdatedEventArgs : EventArgs
        {
            public string OldVersion;
            public string NewVersion;
        }

        public event EventHandler ConfigChanged;
        public event EventHandler EnableStatusChanged;
        public event EventHandler EnableGlobalChanged;
        public event EventHandler ShareOverLANStatusChanged;
        public event EventHandler VerboseLoggingStatusChanged;
        public event EventHandler ShowPluginOutputChanged;

        // when user clicked Edit PAC, and PAC file has already created
        public event EventHandler<PathEventArgs> PACFileReadyToOpen;
        public event EventHandler<PathEventArgs> UserRuleFileReadyToOpen;

        public event EventHandler<GFWListUpdater.ResultEventArgs> UpdatePACFromGFWListCompleted;

        public event ErrorEventHandler UpdatePACFromGFWListError;

        public event ErrorEventHandler Errored;

        // Invoked when controller.Start();
        public event EventHandler<UpdatedEventArgs> ProgramUpdated;

        public ShadowsocksController()
        {
            _config = Configuration.Load();
            StatisticsConfiguration = StatisticsStrategyConfiguration.Load();
            StartReleasingMemory();

            ProgramUpdated += (o, e) =>
            {
                logger.Info($"Updated from {e.OldVersion} to {e.NewVersion}");
            };
        }

        public void Start(bool regHotkeys = true)
        {
            if (_config.updated && regHotkeys)
            {
                _config.updated = false;
                ProgramUpdated.Invoke(this, new UpdatedEventArgs()
                {
                    OldVersion = _config.version,
                    NewVersion = UpdateChecker.Version,
                });
                Configuration.Save(_config);
            }
            Reload();
        }

        protected void ReportError(Exception e)
        {
            Errored?.Invoke(this, new ErrorEventArgs(e));
        }

        public Server GetCurrentServer()
        {
            return _config.GetCurrentServer();
        }

        // always return copy
        public Configuration GetConfigurationCopy()
        {
            return Configuration.Load();
        }

        // always return current instance
        public Configuration GetCurrentConfiguration()
        {
            return _config;
        }

        public void SaveServers(List<Server> servers, int localPort, bool portableMode)
        {
            _config.configs = servers;
            _config.localPort = localPort;
            _config.portableMode = portableMode;
            Configuration.Save(_config);
        }

        public void SaveStrategyConfigurations(StatisticsStrategyConfiguration configuration)
        {
            StatisticsConfiguration = configuration;
            StatisticsStrategyConfiguration.Save(configuration);
        }

        public void ToggleEnable(bool enabled)
        {
            _config.enabled = enabled;
            SaveConfig(_config);

            EnableStatusChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleGlobal(bool global)
        {
            _config.global = global;
            SaveConfig(_config);

            EnableGlobalChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleShareOverLAN(bool enabled)
        {
            _config.shareOverLan = enabled;
            SaveConfig(_config);

            ShareOverLANStatusChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleVerboseLogging(bool enabled)
        {
            _config.isVerboseLogging = enabled;
            SaveConfig(_config);
            NLogConfig.LoadConfiguration(); // reload nlog

            VerboseLoggingStatusChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleShowPluginOutput(bool enabled)
        {
            _config.showPluginOutput = enabled;
            SaveConfig(_config);

            ShowPluginOutputChanged?.Invoke(this, new EventArgs());
        }

        public void SelectServerIndex(int index)
        {
            _config.index = index;
            SaveConfig(_config);
        }

        public void SelectStrategy(string strategyID)
        {
            _config.index = -1;
            SaveConfig(_config);
        }

        public void Stop()
        {
            if (stopped)
            {
                return;
            }
            stopped = true;
            _pacServer.Stop();
            if (privoxyRunner != null)
            {
                privoxyRunner.Stop();
            }
            if (_config.enabled)
            {
                SystemProxy.Update(_config, true, null);
            }
            Encryption.RNG.Close();
        }

        public void TouchPACFile()
        {
            string pacFilename = _pacDaemon.TouchPACFile();

            PACFileReadyToOpen?.Invoke(this, new PathEventArgs() { Path = pacFilename });
        }

        public void TouchUserRuleFile()
        {
            string userRuleFilename = _pacDaemon.TouchUserRuleFile();

            UserRuleFileReadyToOpen?.Invoke(this, new PathEventArgs() { Path = userRuleFilename });
        }

        public void UpdatePACFromGFWList()
        {
            if (gfwListUpdater != null)
            {
                gfwListUpdater.UpdatePACFromGFWList(_config);
            }
        }

        public void SavePACUrl(string pacUrl)
        {
            _config.pacUrl = pacUrl;
            SaveConfig(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void UseOnlinePAC(bool useOnlinePac)
        {
            _config.useOnlinePac = useOnlinePac;
            SaveConfig(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleSecureLocalPac(bool enabled)
        {
            _config.secureLocalPac = enabled;
            SaveConfig(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleCheckingUpdate(bool enabled)
        {
            _config.autoCheckUpdate = enabled;
            Configuration.Save(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleCheckingPreRelease(bool enabled)
        {
            _config.checkPreRelease = enabled;
            Configuration.Save(_config);
            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void SaveLogViewerConfig(LogViewerConfig newConfig)
        {
            _config.logViewer = newConfig;
            newConfig.SaveSize();
            Configuration.Save(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        protected void Reload()
        {
            Encryption.RNG.Reload();
            // some logic in configuration updated the config when saving, we need to read it again
            _config = Configuration.Load();

            NLogConfig.LoadConfiguration();

            StatisticsConfiguration = StatisticsStrategyConfiguration.Load();

            privoxyRunner = privoxyRunner ?? new PrivoxyRunner();

            _pacDaemon = _pacDaemon ?? new PACDaemon();
            _pacDaemon.PACFileChanged += PacDaemon_PACFileChanged;
            _pacDaemon.UserRuleFileChanged += PacDaemon_UserRuleFileChanged;
            _pacServer = _pacServer ?? new PACServer(_pacDaemon);
            _pacServer.UpdatePACURL(_config); // So PACServer works when system proxy disabled.

            gfwListUpdater = gfwListUpdater ?? new GFWListUpdater();
            gfwListUpdater.UpdateCompleted += PacServer_PACUpdateCompleted;
            gfwListUpdater.Error += PacServer_PACUpdateError;

            // don't put PrivoxyRunner.Start() before pacServer.Stop()
            // or bind will fail when switching bind address from 0.0.0.0 to 127.0.0.1
            // though UseShellExecute is set to true now
            // http://stackoverflow.com/questions/10235093/socket-doesnt-close-after-application-exits-if-a-launched-process-is-open
            privoxyRunner.Stop();
            _pacServer.Stop();
            try
            {
                privoxyRunner.Start(this, _config);
                _pacServer.Start(_config);
            }
            catch (Exception e)
            {
                // translate Microsoft language into human language
                // i.e. An attempt was made to access a socket in a way forbidden by its access permissions => Port already in use
                if (e is SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.AddressAlreadyInUse)
                    {
                        e = new Exception(I18N.GetString("Port {0} already in use", _config.localPort), e);
                    }
                    else if (se.SocketErrorCode == SocketError.AccessDenied)
                    {
                        e = new Exception(I18N.GetString("Port {0} is reserved by system", _config.localPort), e);
                    }
                }
                logger.LogUsefulException(e);
                ReportError(e);
            }

            ConfigChanged?.Invoke(this, new EventArgs());
            UpdateSystemProxy();
            Utils.ReleaseMemory(true);
        }

        protected void SaveConfig(Configuration newConfig)
        {
            Configuration.Save(newConfig);
            Reload();
        }

        private void UpdateSystemProxy()
        {
            SystemProxy.Update(_config, false, _pacServer);
        }

        private void PacDaemon_PACFileChanged(object sender, EventArgs e)
        {
            UpdateSystemProxy();
        }

        private void PacServer_PACUpdateCompleted(object sender, GFWListUpdater.ResultEventArgs e)
        {
            UpdatePACFromGFWListCompleted?.Invoke(this, e);
        }

        private void PacServer_PACUpdateError(object sender, ErrorEventArgs e)
        {
            UpdatePACFromGFWListError?.Invoke(this, e);
        }

        private static readonly IEnumerable<char> IgnoredLineBegins = new[] { '!', '[' };
        private void PacDaemon_UserRuleFileChanged(object sender, EventArgs e)
        {
            if (!File.Exists(Utils.GetTempPath("gfwlist.txt")))
            {
                UpdatePACFromGFWList();
            }
            else
            {
                GFWListUpdater.MergeAndWritePACFile(FileManager.NonExclusiveReadAllText(Utils.GetTempPath("gfwlist.txt")));
            }
            UpdateSystemProxy();
        }

        public void CopyPacUrl()
        {
            Clipboard.SetDataObject(_pacServer.PacUrl);
        }

        #region Memory Management

        private void StartReleasingMemory()
        {
            _ramThread = new Thread(new ThreadStart(ReleaseMemory))
            {
                IsBackground = true
            };
            _ramThread.Start();
        }

        private void ReleaseMemory()
        {
            while (true)
            {
                Utils.ReleaseMemory(false);
                Thread.Sleep(30 * 1000);
            }
        }

        #endregion
    }
}
