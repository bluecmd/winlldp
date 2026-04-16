# WinLLDP - LLDP sender for Windows with Hyper-V

A lightweight Windows service that sends LLDP (Link Layer Discovery Protocol)
frames directly on physical network adapters using [npcap](https://npcap.com/),
bypassing Hyper-V virtual switches.

## Why?

On Windows Server with Hyper-V, getting LLDP to work is surprisingly difficult:

- **Intel NICs** (e.g. X552) often don't support the Windows DCB LLDP agent
  (`Enable-NetLldpAgent` fails with "No MSFT_NetLldpAgent objects found")
- **Hyper-V external virtual switches** drop LLDP multicast frames
  (`01:80:c2:00:00:0e`) because they are IEEE 802.1D reserved addresses
  (pktmon shows: "Bridge is not allowed inside VM")
- **WinLLDPService** and similar tools send via the vEthernet adapter,
  which goes through the Hyper-V switch and gets dropped

This service solves both problems by using npcap to inject LLDP frames
directly on the physical adapter's NPF device, completely bypassing the
virtual switch.

## Prerequisites

- Windows Server 2016+ with Hyper-V
- [npcap](https://npcap.com/) (must be installed interactively on Server 2025)
- [SharpPcap](https://github.com/dotpcap/sharppcap) 4.x and PacketDotNet DLLs
  (can be obtained from [WinLLDPService](https://github.com/raspi/WinLLDPService))
- .NET Framework 4.x (included with Windows Server)

## Quick start

```powershell
# 1. Install npcap (interactive, accept defaults)
curl.exe -sLo C:\k\npcap-installer.exe "https://npcap.com/dist/npcap-1.82.exe"
C:\k\npcap-installer.exe

# 2. Get SharpPcap DLLs (from WinLLDPService release)
curl.exe -sLo C:\k\WinLLDPService-x64.msi "https://github.com/raspi/WinLLDPService/releases/download/v17.10.20.2236/WinLLDPService-x64.msi"
msiexec /i C:\k\WinLLDPService-x64.msi /quiet /norestart
Copy-Item "C:\Program Files\WinLLDPService\SharpPcap.dll" C:\k\
Copy-Item "C:\Program Files\WinLLDPService\PacketDotNet.dll" C:\k\

# 3. Compile
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /out:C:\k\LldpSender.exe /reference:C:\k\SharpPcap.dll `
       /reference:C:\k\PacketDotNet.dll C:\k\LldpSender.cs

# 4. Test in console mode
C:\k\LldpSender.exe --console
# Check C:\k\LldpSender.log for output, Ctrl+C to stop

# 5. Install as a service
sc.exe create LldpSender binPath= "C:\k\LldpSender.exe" start= auto
sc.exe description LldpSender "Sends LLDP frames on physical NICs every 30s"
sc.exe failure LldpSender reset= 86400 actions= restart/5000/restart/10000/restart/30000
Start-Service LldpSender
```

## Configuration

By default, the service auto-discovers physical Ethernet adapters and sends
LLDP on all of them.

For explicit control, create `LldpSender.conf` next to the executable:

```
# AdapterGUID,MACAddress,PortName
{7F2D754B-6031-4989-9698-7C5169055D41},0C-C4-7A-CF-AE-9E,Ethernet
{74847FBD-103C-4F34-A4E1-F7F2C84FEB20},0C-C4-7A-CF-AE-9F,Ethernet 2
```

Find your adapter details with:

```powershell
Get-NetAdapter -Physical | Select-Object Name, InterfaceGuid, MacAddress
```

## LLDP TLVs sent

| TLV | Content |
|-----|---------|
| Chassis ID | MAC address (subtype 4) |
| Port ID | Interface name (subtype 5) |
| TTL | 120 seconds |
| System Name | Windows hostname |
| System Description | Windows version |
| Management Address | IPv4 and/or IPv6 unicast address (if available) |

Management addresses are discovered automatically. When a physical NIC is
behind a Hyper-V external virtual switch, the NIC is hidden from .NET's
`NetworkInterface` API. In this case, the service finds the corresponding
`vEthernet` host adapter by matching MAC addresses and reports its IP.
Link-local addresses (169.254.x.x and fe80::) are excluded.

## How it works

The service uses [SharpPcap](https://github.com/dotpcap/sharppcap) (a .NET
wrapper around npcap/libpcap) to open the physical adapter's NPF device
directly. This is the same device path that packet capture tools like Wireshark
use. By sending at this level, the LLDP frame goes straight to the physical
wire without passing through the Hyper-V virtual switch's forwarding engine.

## Troubleshooting

**No LLDP on the switch?**

Use `pktmon` to trace where frames are going:

```powershell
pktmon filter add LLDPFilter --ethertype 0x88CC
pktmon start --capture --pkt-size 128
# Wait 35 seconds
pktmon stop
pktmon format PktMon.etl -o lldp-trace.txt
Select-String -Path lldp-trace.txt -Pattern "LLDP|Drop"
pktmon filter remove
```

**"Bridge is not allowed inside VM"?**

This means frames are going through the Hyper-V vSwitch. The service should
be sending directly on the physical adapter. Check the log to confirm it's
using the `NPF_{GUID}` device for a physical adapter, not a vEthernet adapter.

If needed, you can allow reserved MAC addresses through the vSwitch (requires reboot):

```powershell
$switchId = (Get-VMSwitch).Id
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\VMSMP\Parameters\SwitchList\$switchId"
New-ItemProperty -Path $reg -Name "AllowBridgeReservedMACAddress" -Value 1 -PropertyType DWord -Force
```

## License

MIT
