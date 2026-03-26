$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$fixtureDir = Join-Path $root 'tests\fixtures\pengucore'
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null

function Get-LittleEndianBytes16 {
    param([UInt16]$Value)
    return [BitConverter]::GetBytes($Value)
}

function Get-LittleEndianBytes32 {
    param([UInt32]$Value)
    return [BitConverter]::GetBytes($Value)
}

function Write-PcapFile {
    param(
        [string]$Path,
        [object[]]$Frames
    )

    $bytes = New-Object System.Collections.Generic.List[byte]

    $globalHeader = @(
        0xD4,0xC3,0xB2,0xA1,
        0x02,0x00,
        0x04,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0xFF,0xFF,0x00,0x00,
        0x01,0x00,0x00,0x00
    )
    $bytes.AddRange([byte[]]$globalHeader)

    foreach ($frame in $Frames) {
        $payload = [byte[]]$frame.Bytes
        $bytes.AddRange([byte[]](Get-LittleEndianBytes32 -Value ([UInt32]$frame.Seconds)))
        $bytes.AddRange([byte[]](Get-LittleEndianBytes32 -Value ([UInt32]$frame.Microseconds)))
        $bytes.AddRange([byte[]](Get-LittleEndianBytes32 -Value ([UInt32]$payload.Length)))
        $bytes.AddRange([byte[]](Get-LittleEndianBytes32 -Value ([UInt32]$payload.Length)))
        $bytes.AddRange($payload)
    }

    [System.IO.File]::WriteAllBytes($Path, $bytes.ToArray())
}

function Add-UInt32LE {
    param(
        [System.Collections.Generic.List[byte]]$List,
        [UInt32]$Value
    )
    $List.AddRange([byte[]][BitConverter]::GetBytes($Value))
}

function Add-UInt16LE {
    param(
        [System.Collections.Generic.List[byte]]$List,
        [UInt16]$Value
    )
    $List.AddRange([byte[]][BitConverter]::GetBytes($Value))
}

function Write-PcapNgFile {
    param(
        [string]$Path,
        [object[]]$Frames
    )

    $bytes = New-Object System.Collections.Generic.List[byte]

    $shb = New-Object System.Collections.Generic.List[byte]
    Add-UInt32LE $shb 0x0A0D0D0A
    Add-UInt32LE $shb 28
    Add-UInt32LE $shb 0x1A2B3C4D
    Add-UInt16LE $shb 1
    Add-UInt16LE $shb 0
    $shb.AddRange([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF))
    Add-UInt32LE $shb 28
    $bytes.AddRange($shb.ToArray())

    $idb = New-Object System.Collections.Generic.List[byte]
    Add-UInt32LE $idb 1
    Add-UInt32LE $idb 20
    Add-UInt16LE $idb 1
    Add-UInt16LE $idb 0
    Add-UInt32LE $idb 65535
    Add-UInt32LE $idb 20
    $bytes.AddRange($idb.ToArray())

    foreach ($frame in $Frames) {
        $payload = [byte[]]$frame.Bytes
        $padding = (4 - ($payload.Length % 4)) % 4
        $blockLength = 32 + $payload.Length + $padding

        $epb = New-Object System.Collections.Generic.List[byte]
        Add-UInt32LE $epb 6
        Add-UInt32LE $epb ([UInt32]$blockLength)
        Add-UInt32LE $epb 0

        $timestampMicro = ([UInt64]$frame.Seconds * 1000000) + [UInt64]$frame.Microseconds
        $timestampHigh = [UInt32][math]::Floor([double]$timestampMicro / 4294967296.0)
        $timestampLow = [UInt32]($timestampMicro % 4294967296)
        Add-UInt32LE $epb $timestampHigh
        Add-UInt32LE $epb $timestampLow
        Add-UInt32LE $epb ([UInt32]$payload.Length)
        Add-UInt32LE $epb ([UInt32]$payload.Length)
        $epb.AddRange($payload)
        for ($i = 0; $i -lt $padding; $i++) {
            $epb.Add(0x00)
        }
        Add-UInt32LE $epb ([UInt32]$blockLength)
        $bytes.AddRange($epb.ToArray())
    }

    [System.IO.File]::WriteAllBytes($Path, $bytes.ToArray())
}

$tcpFrame = [PSCustomObject]@{
    Seconds = 1711152000
    Microseconds = 125000
    Bytes = @(
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0x08,0x00,
        0x45,0x00,0x00,0x28,0x00,0x01,0x40,0x00,0x40,0x06,0x00,0x00,0xC0,0xA8,0x01,0x0A,0x5D,0xB8,0xD8,0x22,
        0xC9,0x3A,0x00,0x50,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x50,0x02,0x72,0x10,0x00,0x00,0x00,0x00
    )
}

$dnsQueryPayload = [byte[]]@(
    0x1A,0x2B,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x07,0x65,0x78,0x61,0x6D,0x70,0x6C,0x65,
    0x03,0x63,0x6F,0x6D,
    0x00,
    0x00,0x01,
    0x00,0x01
)
$udpLength = 8 + $dnsQueryPayload.Length
$udpIpTotalLength = 20 + $udpLength
$udpFrameBytes = New-Object System.Collections.Generic.List[byte]
$udpFrameBytes.AddRange([byte[]]@(
    0x10,0x20,0x30,0x40,0x50,0x60,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x08,0x00,
    0x45,0x00
))
$udpFrameBytes.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$udpIpTotalLength)))
$udpFrameBytes.AddRange([byte[]]@(
    0x00,0x02,0x00,0x00,0x40,0x11,0x00,0x00,0xC0,0xA8,0x01,0x14,0x08,0x08,0x08,0x08,
    0xD9,0x03,0x00,0x35
))
$udpFrameBytes.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$udpLength)))
$udpFrameBytes.AddRange([byte[]]@(
    0x00,0x00
))
$udpFrameBytes.AddRange($dnsQueryPayload)

$udpFrame = [PSCustomObject]@{
    Seconds = 1711152001
    Microseconds = 250000
    Bytes = $udpFrameBytes.ToArray()
}

$dnsQueryPayload2 = [byte[]]@(
    0x3C,0x4D,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x04,0x61,0x70,0x69,0x31,
    0x07,0x70,0x65,0x6E,0x67,0x75,0x63,0x6F,0x72,0x65,
    0x03,0x64,0x65,0x76,
    0x00,
    0x00,0x01,
    0x00,0x01
)
$udpLength2 = 8 + $dnsQueryPayload2.Length
$udpIpTotalLength2 = 20 + $udpLength2
$udpFrameBytes2 = New-Object System.Collections.Generic.List[byte]
$udpFrameBytes2.AddRange([byte[]]@(
    0x10,0x20,0x30,0x40,0x50,0x60,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x08,0x00,
    0x45,0x00
))
$udpFrameBytes2.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$udpIpTotalLength2)))
$udpFrameBytes2.AddRange([byte[]]@(
    0x00,0x05,0x00,0x00,0x40,0x11,0x00,0x00,0xC0,0xA8,0x01,0x15,0x01,0x01,0x01,0x01,
    0xD9,0x04,0x00,0x35
))
$udpFrameBytes2.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$udpLength2)))
$udpFrameBytes2.AddRange([byte[]]@(
    0x00,0x00
))
$udpFrameBytes2.AddRange($dnsQueryPayload2)

$udpFrame2 = [PSCustomObject]@{
    Seconds = 1711152001
    Microseconds = 450000
    Bytes = $udpFrameBytes2.ToArray()
}

$httpPayload = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`n`r`n")
$httpIpTotalLength = 20 + 20 + $httpPayload.Length
$httpTcpHeaderLength = 20
$httpFrameBytes = New-Object System.Collections.Generic.List[byte]
$httpFrameBytes.AddRange([byte[]]@(
    0x20,0x21,0x22,0x23,0x24,0x25,0x30,0x31,0x32,0x33,0x34,0x35,0x08,0x00,
    0x45,0x00
))
$httpFrameBytes.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$httpIpTotalLength)))
$httpFrameBytes.AddRange([byte[]]@(
    0x00,0x03,0x00,0x00,0x40,0x06,0x00,0x00,0xC0,0xA8,0x01,0x32,0x5D,0xB8,0xD8,0x22
))
$httpFrameBytes.AddRange([byte[]]@(
    0xC3,0x50,0x00,0x50,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x50,0x18,0x20,0x00,0x00,0x00,0x00,0x00
))
$httpFrameBytes.AddRange([byte[]]$httpPayload)

$httpFrame = [PSCustomObject]@{
    Seconds = 1711152004
    Microseconds = 125000
    Bytes = $httpFrameBytes.ToArray()
}

$httpResponsePayload = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nServer: pengu`r`n`r`n")
$httpResponseIpTotalLength = 20 + 20 + $httpResponsePayload.Length
$httpResponseBytes = New-Object System.Collections.Generic.List[byte]
$httpResponseBytes.AddRange([byte[]]@(
    0x20,0x21,0x22,0x23,0x24,0x25,0x30,0x31,0x32,0x33,0x34,0x35,0x08,0x00,
    0x45,0x00
))
$httpResponseBytes.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$httpResponseIpTotalLength)))
$httpResponseBytes.AddRange([byte[]]@(
    0x00,0x04,0x00,0x00,0x40,0x06,0x00,0x00,0x5D,0xB8,0xD8,0x22,0xC0,0xA8,0x01,0x32
))
$httpResponseBytes.AddRange([byte[]]@(
    0x00,0x50,0xC3,0x50,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x11,0x50,0x18,0x20,0x00,0x00,0x00,0x00,0x00
))
$httpResponseBytes.AddRange([byte[]]$httpResponsePayload)

$httpResponseFrame = [PSCustomObject]@{
    Seconds = 1711152005
    Microseconds = 500000
    Bytes = $httpResponseBytes.ToArray()
}

$httpPayload2 = [System.Text.Encoding]::ASCII.GetBytes("GET /health HTTP/1.1`r`nHost: pengucore.dev`r`n`r`n")
$httpIpTotalLength2 = 20 + 20 + $httpPayload2.Length
$httpFrameBytes2 = New-Object System.Collections.Generic.List[byte]
$httpFrameBytes2.AddRange([byte[]]@(
    0x20,0x21,0x22,0x23,0x24,0x25,0x30,0x31,0x32,0x33,0x34,0x35,0x08,0x00,
    0x45,0x00
))
$httpFrameBytes2.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$httpIpTotalLength2)))
$httpFrameBytes2.AddRange([byte[]]@(
    0x00,0x06,0x00,0x00,0x40,0x06,0x00,0x00,0xC0,0xA8,0x01,0x33,0x5D,0xB8,0xD8,0x22
))
$httpFrameBytes2.AddRange([byte[]]@(
    0xC3,0x51,0x00,0x50,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x00,0x50,0x18,0x20,0x00,0x00,0x00,0x00,0x00
))
$httpFrameBytes2.AddRange([byte[]]$httpPayload2)

$httpFrame2 = [PSCustomObject]@{
    Seconds = 1711152006
    Microseconds = 125000
    Bytes = $httpFrameBytes2.ToArray()
}

$httpResponsePayload2 = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 204 No Content`r`nServer: pengu`r`n`r`n")
$httpResponseIpTotalLength2 = 20 + 20 + $httpResponsePayload2.Length
$httpResponseBytes2 = New-Object System.Collections.Generic.List[byte]
$httpResponseBytes2.AddRange([byte[]]@(
    0x20,0x21,0x22,0x23,0x24,0x25,0x30,0x31,0x32,0x33,0x34,0x35,0x08,0x00,
    0x45,0x00
))
$httpResponseBytes2.AddRange([byte[]][BitConverter]::GetBytes([UInt16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$httpResponseIpTotalLength2)))
$httpResponseBytes2.AddRange([byte[]]@(
    0x00,0x07,0x00,0x00,0x40,0x06,0x00,0x00,0x5D,0xB8,0xD8,0x22,0xC0,0xA8,0x01,0x33
))
$httpResponseBytes2.AddRange([byte[]]@(
    0x00,0x50,0xC3,0x51,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x31,0x50,0x18,0x20,0x00,0x00,0x00,0x00,0x00
))
$httpResponseBytes2.AddRange([byte[]]$httpResponsePayload2)

$httpResponseFrame2 = [PSCustomObject]@{
    Seconds = 1711152006
    Microseconds = 325000
    Bytes = $httpResponseBytes2.ToArray()
}

$arpFrame = [PSCustomObject]@{
    Seconds = 1711152002
    Microseconds = 500000
    Bytes = @(
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x66,0x77,0x88,0x99,0xAA,0xBB,0x08,0x06,
        0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,
        0x66,0x77,0x88,0x99,0xAA,0xBB,0xC0,0xA8,0x01,0x0A,
        0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0xA8,0x01,0x01
    )
}

$shortFrame = [PSCustomObject]@{
    Seconds = 1711152003
    Microseconds = 750000
    Bytes = @(0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08)
}

Write-PcapFile -Path (Join-Path $fixtureDir 'tcp_ipv4_sample.pcap') -Frames @($tcpFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'udp_ipv4_sample.pcap') -Frames @($udpFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'arp_sample.pcap') -Frames @($arpFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'short_frame_sample.pcap') -Frames @($shortFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'http_ipv4_sample.pcap') -Frames @($httpFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'http_response_sample.pcap') -Frames @($httpResponseFrame)
Write-PcapFile -Path (Join-Path $fixtureDir 'multi_dns_sample.pcap') -Frames @($udpFrame, $udpFrame2)
Write-PcapFile -Path (Join-Path $fixtureDir 'http_exchange_sample.pcap') -Frames @($httpFrame, $httpResponseFrame, $httpFrame2, $httpResponseFrame2)
Write-PcapFile -Path (Join-Path $fixtureDir 'mixed_sample.pcap') -Frames @($tcpFrame, $udpFrame, $udpFrame2, $arpFrame, $shortFrame, $httpFrame, $httpResponseFrame, $httpFrame2, $httpResponseFrame2)
Write-PcapNgFile -Path (Join-Path $fixtureDir 'pcapng_http_sample.pcapng') -Frames @($httpFrame)

Write-Output "PenguCore fixture pcap files generated in: $fixtureDir"
