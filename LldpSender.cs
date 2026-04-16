using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;
using SharpPcap;

/// <summary>
/// Windows service that sends LLDP frames directly on physical network adapters
/// using npcap, bypassing Hyper-V virtual switches.
///
/// This is useful when:
///  - The NIC does not support Windows DCB LLDP agents (e.g. Intel X552)
///  - A Hyper-V external virtual switch drops IEEE 802.1D reserved multicast
///    frames ("Bridge is not allowed inside VM")
///
/// Prerequisites:
///  - npcap (https://npcap.com/)
///  - SharpPcap.dll and PacketDotNet.dll in the same directory as the executable
///
/// Configuration:
///  - Place a file named LldpSender.conf next to the executable
///  - Each non-empty, non-comment line is: AdapterGUID,MACAddress,PortName
///  - If no config file exists, the service auto-discovers physical adapters
///
/// Usage:
///  - As a service:  sc.exe create LldpSender binPath= "C:\k\LldpSender.exe"
///  - Console mode:  LldpSender.exe --console
/// </summary>
public class LldpSender : ServiceBase
{
    private Thread _worker;
    private bool _running;
    private string _baseDir;
    private List<AdapterInfo> _adapters;

    static readonly byte[] LldpMulticast = new byte[] { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
    const int SendIntervalMs = 30000;
    const int TtlSeconds = 120;

    public LldpSender()
    {
        ServiceName = "LldpSender";
        _baseDir = AppDomain.CurrentDomain.BaseDirectory;
    }

    protected override void OnStart(string[] args)
    {
        _running = true;
        _worker = new Thread(Run);
        _worker.IsBackground = true;
        _worker.Start();
    }

    protected override void OnStop()
    {
        _running = false;
        if (_worker != null) _worker.Join(5000);
    }

    private void Run()
    {
        Log("Service starting");
        _adapters = LoadAdapters();
        Log("Configured adapters: " + _adapters.Count);
        foreach (AdapterInfo a in _adapters)
        {
            Log("  " + a.PortName + " GUID=" + a.Guid + " MAC=" + a.MacHex);
        }

        while (_running)
        {
            try { SendOnAdapters(_adapters); }
            catch (Exception ex) { Log("Error: " + ex.ToString()); }
            for (int i = 0; i < SendIntervalMs / 1000 && _running; i++)
                Thread.Sleep(1000);
        }
        Log("Service stopping");
    }

    private List<AdapterInfo> LoadAdapters()
    {
        string confPath = Path.Combine(_baseDir, "LldpSender.conf");
        if (File.Exists(confPath))
        {
            return LoadFromConfig(confPath);
        }
        Log("No config file found at " + confPath + ", auto-discovering physical adapters");
        return AutoDiscover();
    }

    private List<AdapterInfo> LoadFromConfig(string path)
    {
        List<AdapterInfo> result = new List<AdapterInfo>();
        foreach (string rawLine in File.ReadAllLines(path))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            string[] parts = line.Split(new char[] { ',' }, 3);
            if (parts.Length < 3)
            {
                Log("Skipping malformed config line: " + line);
                continue;
            }
            result.Add(new AdapterInfo
            {
                Guid = parts[0].Trim(),
                MacHex = parts[1].Trim().Replace("-", "").Replace(":", ""),
                PortName = parts[2].Trim()
            });
        }
        return result;
    }

    private List<AdapterInfo> AutoDiscover()
    {
        List<AdapterInfo> result = new List<AdapterInfo>();
        var devices = CaptureDeviceList.Instance;

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet &&
                nic.NetworkInterfaceType != NetworkInterfaceType.GigabitEthernet)
                continue;
            if (nic.Description.IndexOf("Hyper-V", StringComparison.OrdinalIgnoreCase) >= 0)
                continue;
            if (nic.Description.IndexOf("Virtual", StringComparison.OrdinalIgnoreCase) >= 0)
                continue;

            // Check if npcap has a device for this adapter
            bool foundInPcap = false;
            foreach (ICaptureDevice dev in devices)
            {
                if (dev.Name.IndexOf(nic.Id, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    foundInPcap = true;
                    break;
                }
            }
            if (!foundInPcap) continue;

            byte[] macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            if (macBytes.Length != 6) continue;

            string macHex = BitConverter.ToString(macBytes).Replace("-", "");
            result.Add(new AdapterInfo
            {
                Guid = nic.Id,
                MacHex = macHex,
                PortName = nic.Name
            });
        }
        return result;
    }

    private void SendOnAdapters(List<AdapterInfo> adapters)
    {
        var devices = CaptureDeviceList.Instance;
        foreach (AdapterInfo adapter in adapters)
        {
            ICaptureDevice matchedDev = null;
            foreach (ICaptureDevice dev in devices)
            {
                if (dev.Name.IndexOf(adapter.Guid, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    matchedDev = dev;
                    break;
                }
            }
            if (matchedDev == null)
            {
                Log("Device not found for " + adapter.PortName + " (" + adapter.Guid + ")");
                continue;
            }

            byte[] mac = ParseMac(adapter.MacHex);
            if (mac == null)
            {
                Log("Invalid MAC for " + adapter.PortName + ": " + adapter.MacHex);
                continue;
            }

            List<IPAddress> mgmtAddrs = GetManagementAddresses(adapter.Guid);

            try
            {
                matchedDev.Open(DeviceMode.Promiscuous);
                byte[] frame = BuildLldpFrame(mac, Environment.MachineName, adapter.PortName, mgmtAddrs);
                matchedDev.SendPacket(frame);
                matchedDev.Close();
                Log("Sent LLDP on " + adapter.PortName + " MAC=" + BitConverter.ToString(mac)
                    + " mgmt=" + string.Join(",", mgmtAddrs.ConvertAll(a => a.ToString()).ToArray()));
            }
            catch (Exception ex)
            {
                try { matchedDev.Close(); } catch { }
                Log("Failed on " + adapter.PortName + ": " + ex.Message);
            }
        }
    }

    /// <summary>
    /// Find management addresses for the given adapter.
    /// Checks the adapter itself first, then falls back to any adapter
    /// whose MAC matches (handles Hyper-V vSwitch where the physical NIC
    /// is hidden from .NET and IPs live on the vEthernet adapter sharing
    /// the physical adapter's MAC).
    /// Returns at most one IPv4 and one IPv6 address.
    /// </summary>
    private List<IPAddress> GetManagementAddresses(string adapterGuid)
    {
        List<IPAddress> result = new List<IPAddress>();
        byte[] targetMac = ParseMac(GetMacForAdapter(adapterGuid));

        // Try the adapter itself first (if visible to .NET)
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (string.Equals(nic.Id, adapterGuid, StringComparison.OrdinalIgnoreCase))
            {
                if (targetMac == null)
                    targetMac = nic.GetPhysicalAddress().GetAddressBytes();
                CollectAddresses(nic, result);
                break;
            }
        }

        // If we found addresses directly, use those
        if (result.Count > 0) return result;

        // Otherwise look for any adapter with the same MAC
        // (Hyper-V external switch hides the physical NIC from .NET but
        // the vEthernet host adapter shares the same MAC and holds the IPs)
        if (targetMac != null && targetMac.Length == 6)
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (string.Equals(nic.Id, adapterGuid, StringComparison.OrdinalIgnoreCase))
                    continue;
                byte[] nicMac = nic.GetPhysicalAddress().GetAddressBytes();
                if (nicMac.Length == 6 && MacEqual(nicMac, targetMac))
                {
                    CollectAddresses(nic, result);
                    if (result.Count > 0) break;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Look up the MAC for an adapter from the known adapter list.
    /// This handles the case where the physical NIC is hidden from
    /// NetworkInterface.GetAllNetworkInterfaces() by a Hyper-V vSwitch.
    /// </summary>
    private string GetMacForAdapter(string adapterGuid)
    {
        if (_adapters == null) return null;
        foreach (AdapterInfo a in _adapters)
        {
            if (string.Equals(a.Guid, adapterGuid, StringComparison.OrdinalIgnoreCase))
                return a.MacHex;
        }
        return null;
    }

    private static void CollectAddresses(NetworkInterface nic, List<IPAddress> result)
    {
        IPInterfaceProperties props = nic.GetIPProperties();
        bool hasV4 = false;
        bool hasV6 = false;
        foreach (UnicastIPAddressInformation addr in props.UnicastAddresses)
        {
            if (!hasV4 && addr.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                // Skip link-local (169.254.0.0/16)
                byte[] bytes = addr.Address.GetAddressBytes();
                if (bytes[0] == 169 && bytes[1] == 254) continue;
                result.Add(addr.Address);
                hasV4 = true;
            }
            else if (!hasV6 && addr.Address.AddressFamily == AddressFamily.InterNetworkV6
                     && !addr.Address.IsIPv6LinkLocal)
            {
                result.Add(addr.Address);
                hasV6 = true;
            }
            if (hasV4 && hasV6) break;
        }
    }

    private static bool MacEqual(byte[] a, byte[] b)
    {
        for (int i = 0; i < 6; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    private string _logPath;

    private void Log(string msg)
    {
        if (_logPath == null)
            _logPath = Path.Combine(_baseDir, "LldpSender.log");
        try
        {
            File.AppendAllText(_logPath,
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + msg + Environment.NewLine);
        }
        catch { }
    }

    static byte[] ParseMac(string hex)
    {
        hex = hex.Replace("-", "").Replace(":", "");
        if (hex.Length != 12) return null;
        byte[] mac = new byte[6];
        for (int i = 0; i < 6; i++)
        {
            mac[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return mac;
    }

    static byte[] BuildLldpFrame(byte[] srcMac, string sysName, string portName,
        List<IPAddress> mgmtAddrs)
    {
        List<byte[]> tlvs = new List<byte[]>();

        // Chassis ID TLV (type 1, subtype 4 = MAC address)
        tlvs.Add(MakeTlv(1, Concat(new byte[] { 4 }, srcMac)));

        // Port ID TLV (type 2, subtype 5 = interface name)
        tlvs.Add(MakeTlv(2, Concat(new byte[] { 5 },
            System.Text.Encoding.ASCII.GetBytes(portName))));

        // TTL TLV (type 3)
        tlvs.Add(MakeTlv(3, new byte[] {
            (byte)(TtlSeconds >> 8), (byte)(TtlSeconds & 0xFF) }));

        // System Name TLV (type 5)
        tlvs.Add(MakeTlv(5, System.Text.Encoding.ASCII.GetBytes(sysName)));

        // System Description TLV (type 6)
        tlvs.Add(MakeTlv(6, System.Text.Encoding.ASCII.GetBytes(
            "Windows " + Environment.OSVersion.Version.ToString())));

        // Management Address TLVs (type 8)
        foreach (IPAddress addr in mgmtAddrs)
        {
            tlvs.Add(BuildMgmtAddrTlv(addr));
        }

        // End TLV (type 0)
        tlvs.Add(new byte[] { 0, 0 });

        int payloadLen = 0;
        foreach (byte[] t in tlvs) payloadLen += t.Length;
        int frameLen = 14 + payloadLen;
        if (frameLen < 60) frameLen = 60;

        byte[] frame = new byte[frameLen];
        Array.Copy(LldpMulticast, 0, frame, 0, 6);
        Array.Copy(srcMac, 0, frame, 6, 6);
        frame[12] = 0x88;
        frame[13] = 0xCC;

        int offset = 14;
        foreach (byte[] tlv in tlvs)
        {
            Array.Copy(tlv, 0, frame, offset, tlv.Length);
            offset += tlv.Length;
        }
        return frame;
    }

    /// <summary>
    /// Build a Management Address TLV (type 8) per IEEE 802.1AB.
    /// Layout:
    ///   1 byte  - management address string length (1 + addr bytes)
    ///   1 byte  - address subtype (1 = IPv4, 2 = IPv6, per IANA ianaAddressFamilyNumbers)
    ///   N bytes - address
    ///   1 byte  - interface numbering subtype (2 = ifIndex)
    ///   4 bytes - interface number (0 = unknown)
    ///   1 byte  - OID string length (0 = none)
    /// </summary>
    static byte[] BuildMgmtAddrTlv(IPAddress addr)
    {
        byte[] addrBytes = addr.GetAddressBytes();
        // IANA address family: 1 = IPv4, 2 = IPv6
        byte addrSubtype = (byte)(addr.AddressFamily == AddressFamily.InterNetwork ? 1 : 2);
        byte addrStrLen = (byte)(1 + addrBytes.Length);

        // Total value: addrStrLen(1) + subtype(1) + addr(N) + ifSubtype(1) + ifNumber(4) + oidLen(1)
        byte[] value = new byte[1 + 1 + addrBytes.Length + 1 + 4 + 1];
        int pos = 0;
        value[pos++] = addrStrLen;
        value[pos++] = addrSubtype;
        Array.Copy(addrBytes, 0, value, pos, addrBytes.Length);
        pos += addrBytes.Length;
        value[pos++] = 2; // interface numbering subtype: ifIndex
        // interface number: 0 (unknown)
        value[pos++] = 0;
        value[pos++] = 0;
        value[pos++] = 0;
        value[pos++] = 0;
        value[pos++] = 0; // OID string length: 0

        return MakeTlv(8, value);
    }

    static byte[] MakeTlv(int type, byte[] value)
    {
        int len = value.Length;
        int header = (type << 9) | len;
        byte[] tlv = new byte[2 + len];
        tlv[0] = (byte)(header >> 8);
        tlv[1] = (byte)(header & 0xFF);
        Array.Copy(value, 0, tlv, 2, len);
        return tlv;
    }

    static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.Length + b.Length];
        Array.Copy(a, r, a.Length);
        Array.Copy(b, 0, r, a.Length, b.Length);
        return r;
    }

    public static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--console")
        {
            LldpSender svc = new LldpSender();
            svc._running = true;
            svc.Run();
        }
        else
        {
            ServiceBase.Run(new LldpSender());
        }
    }
}

class AdapterInfo
{
    public string Guid;
    public string MacHex;
    public string PortName;
}
