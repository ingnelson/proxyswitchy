using Shadowsocks.Controller;
using Shadowsocks.Model;
using Shadowsocks.Properties;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Shadowsocks.View
{
    public partial class ConfigForm : Form
    {
        private ShadowsocksController controller;

        // this is a copy of configuration that we are working on
        private Configuration _modifiedConfiguration;
        private int _lastSelectedIndex = -1;

        private bool isChange = false;

        public ConfigForm(ShadowsocksController controller)
        {
            Font = SystemFonts.MessageBoxFont;
            InitializeComponent();

            // a dirty hack
            ServersListBox.Dock = DockStyle.Fill;
            tableLayoutPanel5.Dock = DockStyle.Fill;
            PerformLayout();

            UpdateTexts();
            SetupValueChangedListeners();
            Icon = Icon.FromHandle(Resources.ssw128.GetHicon());

            this.controller = controller;
            controller.ConfigChanged += Controller_ConfigChanged;

            LoadCurrentConfiguration();
        }

        private void UpdateTexts()
        {
            I18N.TranslateForm(this);
            toolTip1.SetToolTip(PortableModeCheckBox, I18N.GetString("Restart required"));
        }

        private void SetupValueChangedListeners()
        {
            IPTextBox.TextChanged += ConfigValueChanged;
            ProxyPortTextBox.TextChanged += ConfigValueChanged;
            RemarksTextBox.TextChanged += ConfigValueChanged;
            PortableModeCheckBox.CheckedChanged += ConfigValueChanged;
            ServerPortTextBox.TextChanged += ConfigValueChanged;
        }

        private void Controller_ConfigChanged(object sender, EventArgs e)
        {
            LoadCurrentConfiguration();
        }

        private void ConfigValueChanged(object sender, EventArgs e)
        {
            isChange = true;
            ApplyButton.Enabled = true;
        }

        private bool ValidateAndSaveSelectedServerDetails(bool isSave = false, bool isCopy = false)
        {
            try
            {
                if (_lastSelectedIndex == -1 || _lastSelectedIndex >= _modifiedConfiguration.configs.Count)
                {
                    return true;
                }

                bool verify = GetServerDetailsFromUI(out Server server, isSave, isCopy);

                if (server != null)
                {
                    if (isSave || isCopy)
                        Configuration.CheckServer(server);

                    _modifiedConfiguration.configs[_lastSelectedIndex] = server;
                }
                return verify;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            return false;
        }

        private bool GetServerDetailsFromUI(out Server server, bool isSave = false, bool isCopy = false)
        {
            server = null;

            bool? checkIP = false;
            bool? checkPort = false;

            if ((checkIP = CheckIPTextBox(out string address, isSave, isCopy)).GetValueOrDefault(false) && address != null
                    && (checkPort = CheckServerPortTextBox(out int? addressPort, isSave, isCopy)).GetValueOrDefault(false) && addressPort.HasValue)
            {
                server = new Server()
                {
                    server = address,
                    server_port = addressPort.Value,
                    remarks = RemarksTextBox.Text,
                };

                return true;
            }

            if (checkIP == null || checkPort == null)
            {
                _modifiedConfiguration.configs.RemoveAt(_lastSelectedIndex);
                ServersListBox.SelectedIndexChanged -= ServersListBox_SelectedIndexChanged;

                int lastIndex = ServersListBox.SelectedIndex;

                LoadServerNameListToUI(_modifiedConfiguration);

                _lastSelectedIndex = (ServersListBox.SelectedIndex = (_lastSelectedIndex == ServersListBox.Items.Count ? lastIndex : lastIndex - 1));

                ServersListBox.SelectedIndexChanged += ServersListBox_SelectedIndexChanged;
                return true;
            }
            else
                return false;
        }

        #region GetServerDetailsFromUI Check

        private bool? CheckIPTextBox(out string address, bool isSave, bool isCopy)
        {
            address = null;
            string outAddress;
            if (Uri.CheckHostName(outAddress = IPTextBox.Text.Trim()) == UriHostNameType.Unknown)
            {
                if (!isSave && !isCopy && ServersListBox.Items.Count > 1 && I18N.GetString("New server").Equals(ServersListBox.Items[_lastSelectedIndex].ToString()))
                {
                    DialogResult result = MessageBox.Show(I18N.GetString("Whether to discard unconfigured servers"), I18N.GetString("Operation failure"), MessageBoxButtons.OKCancel);

                    if (result == DialogResult.OK)
                        return null;
                }
                else if (isChange && !isSave && !isCopy)
                {
                    var result = MessageBox.Show(I18N.GetString("Invalid server address, Cannot automatically save or discard changes"), I18N.GetString("Auto save failed"), MessageBoxButtons.OKCancel);

                    if (result == DialogResult.Cancel)
                        return false;
                    else
                    {
                        address = _modifiedConfiguration.configs[_lastSelectedIndex].server;
                        return true;
                    }
                }
                else
                {
                    MessageBox.Show(I18N.GetString("Invalid server address"), I18N.GetString("Operation failure"));
                    IPTextBox.Focus();
                }
                return false;
            }
            else
            {
                address = outAddress;
            }
            return true;
        }

        private bool? CheckServerPortTextBox(out int? addressPort, bool isSave, bool isCopy)
        {
            addressPort = null;
            if (!int.TryParse(ServerPortTextBox.Text, out int outaddressPort))
            {
                if (!isSave && !isCopy && ServersListBox.Items.Count > 1 && I18N.GetString("New server").Equals(ServersListBox.Items[_lastSelectedIndex].ToString()))
                {
                    DialogResult result = MessageBox.Show(I18N.GetString("Whether to discard unconfigured servers"), I18N.GetString("Operation failure"), MessageBoxButtons.OKCancel);

                    if (result == DialogResult.OK)
                        return null;
                }
                else if (isChange && !isSave && !isCopy)
                {
                    var result = MessageBox.Show(I18N.GetString("Illegal port number format, Cannot automatically save or discard changes"), I18N.GetString("Auto save failed"), MessageBoxButtons.OKCancel);

                    if (result == DialogResult.Cancel)
                        return false;
                    else
                    {
                        addressPort = _modifiedConfiguration.configs[_lastSelectedIndex].server_port;
                        return true;
                    }
                }
                else
                {
                    MessageBox.Show(I18N.GetString("Illegal port number format"), I18N.GetString("Operation failure"));
                    ServerPortTextBox.Focus();
                }
                return false;
            }
            else
            {
                addressPort = outaddressPort;
            }
            return true;
        }

        #endregion

        private void LoadSelectedServerDetails()
        {
            if (ServersListBox.SelectedIndex >= 0 && ServersListBox.SelectedIndex < _modifiedConfiguration.configs.Count)
            {
                Server server = _modifiedConfiguration.configs[ServersListBox.SelectedIndex];
                SetServerDetailsToUI(server);
            }
        }

        private void SetServerDetailsToUI(Server server)
        {
            IPTextBox.Text = server.server;
            ServerPortTextBox.Text = server.server_port.ToString();
            RemarksTextBox.Text = server.remarks;

            isChange = false;
        }

        private void LoadServerNameListToUI(Configuration configuration)
        {
            ServersListBox.Items.Clear();
            foreach (Server server in configuration.configs)
            {
                ServersListBox.Items.Add(server.FriendlyName());
            }
        }

        private void LoadCurrentConfiguration()
        {
            _modifiedConfiguration = controller.GetConfigurationCopy();
            LoadServerNameListToUI(_modifiedConfiguration);

            _lastSelectedIndex = _modifiedConfiguration.index;
            if (_lastSelectedIndex < 0 || _lastSelectedIndex >= ServersListBox.Items.Count)
            {
                _lastSelectedIndex = 0;
            }

            ServersListBox.SelectedIndex = _lastSelectedIndex;
            UpdateButtons();
            LoadSelectedServerDetails();

            ProxyPortTextBox.Text = _modifiedConfiguration.localPort.ToString();
            PortableModeCheckBox.Checked = _modifiedConfiguration.portableMode;

            ApplyButton.Enabled = false;
        }

        private bool SaveValidConfiguration()
        {
            if (!ValidateAndSaveSelectedServerDetails(isSave: true))
            {
                return false;
            }

            int localPort = int.Parse(ProxyPortTextBox.Text);
            Configuration.CheckLocalPort(localPort);
            _modifiedConfiguration.localPort = localPort;

            _modifiedConfiguration.portableMode = PortableModeCheckBox.Checked;

            controller.SaveServers(_modifiedConfiguration.configs, _modifiedConfiguration.localPort, _modifiedConfiguration.portableMode);
            // SelectedIndex remains valid
            // We handled this in event handlers, e.g. Add/DeleteButton, SelectedIndexChanged
            // and move operations
            controller.SelectServerIndex(ServersListBox.SelectedIndex);
            return true;
        }

        private void ConfigForm_KeyDown(object sender, KeyEventArgs e)
        {
            // Sometimes the users may hit enter key by mistake, and the form will close without saving entries.

            if (e.KeyCode == Keys.Enter)
            {
                SaveValidConfiguration();
            }
        }

        private void ServersListBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (!ServersListBox.CanSelect)
            {
                return;
            }
            if (_lastSelectedIndex == ServersListBox.SelectedIndex)
            {
                // we are moving back to oldSelectedIndex or doing a force move
                return;
            }
            if (!ValidateAndSaveSelectedServerDetails())
            {
                // why this won't cause stack overflow?
                ServersListBox.SelectedIndex = _lastSelectedIndex;
                return;
            }
            if (_lastSelectedIndex >= 0 && _lastSelectedIndex < _modifiedConfiguration.configs.Count)
            {
                ServersListBox.Items[_lastSelectedIndex] = _modifiedConfiguration.configs[_lastSelectedIndex].FriendlyName();
            }
            UpdateButtons();
            LoadSelectedServerDetails();
            _lastSelectedIndex = ServersListBox.SelectedIndex;
        }

        private void AddButton_Click(object sender, EventArgs e)
        {
            if (ValidateAndSaveSelectedServerDetails(isSave: true))
            {
                Configuration.AddDefaultServerOrServer(_modifiedConfiguration);
                LoadServerNameListToUI(_modifiedConfiguration);
                _lastSelectedIndex = (ServersListBox.SelectedIndex = _modifiedConfiguration.configs.Count - 1);
            }
        }

        private void DuplicateButton_Click(object sender, EventArgs e)
        {
            if (ValidateAndSaveSelectedServerDetails(isCopy: true))
            {
                Server currServer = _modifiedConfiguration.configs[_lastSelectedIndex];
                Configuration.AddDefaultServerOrServer(_modifiedConfiguration, currServer, _lastSelectedIndex + 1);
                LoadServerNameListToUI(_modifiedConfiguration);
                _lastSelectedIndex = (ServersListBox.SelectedIndex = (_lastSelectedIndex + 1));
            }
        }

        private void DeleteButton_Click(object sender, EventArgs e)
        {
            _modifiedConfiguration.configs.RemoveAt(_lastSelectedIndex);

            if (_modifiedConfiguration.configs.Count == 0)
            {
                Configuration.AddDefaultServerOrServer(_modifiedConfiguration);
            }

            LoadServerNameListToUI(_modifiedConfiguration);
            ServersListBox.SelectedIndexChanged -= ServersListBox_SelectedIndexChanged;

            _lastSelectedIndex = (ServersListBox.SelectedIndex = (_lastSelectedIndex >= _modifiedConfiguration.configs.Count ? (_modifiedConfiguration.configs.Count - 1) : _lastSelectedIndex));

            ServersListBox.SelectedIndexChanged += ServersListBox_SelectedIndexChanged;
            LoadSelectedServerDetails();

            UpdateButtons();
        }

        private void UpdateButtons()
        {
            DeleteButton.Enabled = (ServersListBox.Items.Count > 0);
            MoveUpButton.Enabled = (ServersListBox.SelectedIndex > 0);
            MoveDownButton.Enabled = (ServersListBox.SelectedIndex < ServersListBox.Items.Count - 1);
        }

        private void MoveUpButton_Click(object sender, EventArgs e)
        {
            if (ServersListBox.SelectedIndex > 0)
            {
                MoveConfigItem(-1);  // -1 means move backward
            }
        }

        private void MoveDownButton_Click(object sender, EventArgs e)
        {
            if (ServersListBox.SelectedIndex < ServersListBox.Items.Count - 1)
            {
                MoveConfigItem(+1);  // +1 means move forward
            }
        }

        private void MoveConfigItem(int step)
        {
            var server = _modifiedConfiguration.configs[_lastSelectedIndex];
            var newIndex = _lastSelectedIndex + step;

            _modifiedConfiguration.configs.RemoveAt(_lastSelectedIndex);
            _modifiedConfiguration.configs.Insert(newIndex, server);

            ServersListBox.BeginUpdate();

            LoadServerNameListToUI(_modifiedConfiguration);

            _lastSelectedIndex = newIndex;
            ServersListBox.SelectedIndex = newIndex;
            ServersListBox.EndUpdate();

            UpdateButtons();
        }

        private void OKButton_Click(object sender, EventArgs e)
        {
            if (SaveValidConfiguration())
            {
                Close();
            }
        }

        private void CancelButton_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            SaveValidConfiguration();
        }

        private void ConfigForm_Shown(object sender, EventArgs e)
        {
            IPTextBox.Focus();
        }

        private void ConfigForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            controller.ConfigChanged -= Controller_ConfigChanged;
        }
    }
}
