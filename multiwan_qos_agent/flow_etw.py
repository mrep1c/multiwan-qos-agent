"""
Windows ETW UDP flow telemetry collector.

This is metadata telemetry, not packet capture. It subscribes to the built-in
Microsoft-Windows-Kernel-Network provider and consumes UDP flow events only.
The collector is best-effort: if ETW cannot be started, callers continue with
psutil live-flow detection and expose failures in the dashboard.
"""

import ctypes
import ipaddress
import logging
import os
import socket
import threading
import time
import uuid
from ctypes import wintypes

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("multiwan_qos_agent.flow_etw")

WINDOW_SECONDS = 45
MIN_FLOW_AGE = 3
STALE_SECONDS = 15
MIN_BYTES_PER_SECOND = 4094
TOP_FLOW_RATIO = 0.50
MAX_SELECTED_FLOWS = 3

IGNORED_UDP_PORTS = {
    53,      # DNS
    67, 68,  # DHCP
    123,     # NTP
    137, 138,
    1900,    # SSDP
    5353,    # mDNS
    5355,    # LLMNR
}

# Microsoft-Windows-Kernel-Network UDP events from the provider manifest:
# 42/43 are UDPv4 send/recv; 58/59 are UDPv6 send/recv.
UDP_EVENT_IDS = {42, 43, 58, 59}
SEND_EVENT_IDS = {42, 58}
RECV_EVENT_IDS = {43, 59}
IPV6_EVENT_IDS = {58, 59}

ERROR_SUCCESS = 0
ERROR_ALREADY_EXISTS = 183
ERROR_INSUFFICIENT_BUFFER = 122
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
TRACE_LEVEL_INFORMATION = 4
WNODE_FLAG_TRACED_GUID = 0x00020000
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF

SESSION_NAME = "MultiWANQoSAgentUdpFlow"
KERNEL_NETWORK_GUID = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
KERNEL_NETWORK_KEYWORDS = 0  # Enable provider broadly; filter UDP events in-process.

AF_INET = 2
AF_INET6 = 23
UDP_TABLE_OWNER_PID = 1


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid(value):
    parsed = uuid.UUID(value)
    data4 = (ctypes.c_ubyte * 8).from_buffer_copy(parsed.bytes[8:])
    return GUID(parsed.time_low, parsed.time_mid, parsed.time_hi_version, data4)


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("ProviderId", wintypes.ULONG),
        ("HistoricalContext", ctypes.c_ulonglong),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", GUID),
        ("ClientContext", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", wintypes.ULONG),
        ("MinimumBuffers", wintypes.ULONG),
        ("MaximumBuffers", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("FlushTimer", wintypes.ULONG),
        ("EnableFlags", wintypes.ULONG),
        ("AgeLimit", ctypes.c_long),
        ("NumberOfBuffers", wintypes.ULONG),
        ("FreeBuffers", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogBuffersLost", wintypes.ULONG),
        ("RealTimeBuffersLost", wintypes.ULONG),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", wintypes.ULONG),
        ("LoggerNameOffset", wintypes.ULONG),
    ]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", wintypes.USHORT),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", wintypes.USHORT),
        ("Keyword", ctypes.c_ulonglong),
    ]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("HeaderType", wintypes.USHORT),
        ("Flags", wintypes.USHORT),
        ("EventProperty", wintypes.USHORT),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", ctypes.c_longlong),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", wintypes.ULONG),
        ("UserTime", wintypes.ULONG),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
        ("LoggerId", wintypes.USHORT),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", wintypes.USHORT),
        ("UserDataLength", wintypes.USHORT),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class PROPERTY_DATA_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("PropertyName", ctypes.c_ulonglong),
        ("ArrayIndex", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("FieldTypeFlags", wintypes.USHORT),
        ("Version", wintypes.ULONG),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", GUID),
        ("ClientContext", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", wintypes.ULONG),
        ("ParentInstanceId", wintypes.ULONG),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", wintypes.ULONG),
        ("ClientContext", wintypes.ULONG),
    ]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Bias", wintypes.LONG),
        ("StandardName", wintypes.WCHAR * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", wintypes.LONG),
        ("DaylightName", wintypes.WCHAR * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", wintypes.LONG),
    ]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("Version", wintypes.ULONG),
        ("ProviderVersion", wintypes.ULONG),
        ("NumberOfProcessors", wintypes.ULONG),
        ("EndTime", ctypes.c_longlong),
        ("TimerResolution", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogInstanceGuid", GUID),
        ("LoggerName", wintypes.LPWSTR),
        ("LogFileName", wintypes.LPWSTR),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", ctypes.c_longlong),
        ("PerfFreq", ctypes.c_longlong),
        ("StartTime", ctypes.c_longlong),
        ("ReservedFlags", wintypes.ULONG),
        ("BuffersLost", wintypes.ULONG),
    ]


EVENT_RECORD_CALLBACK = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(
    None, ctypes.POINTER(EVENT_RECORD)
)


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", wintypes.LPWSTR),
        ("LoggerName", wintypes.LPWSTR),
        ("CurrentTime", ctypes.c_longlong),
        ("BuffersRead", wintypes.ULONG),
        ("ProcessTraceMode", wintypes.ULONG),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", wintypes.ULONG),
        ("Filled", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("EventRecordCallback", EVENT_RECORD_CALLBACK),
        ("IsKernelTrace", wintypes.ULONG),
        ("Context", ctypes.c_void_p),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


def _configure_etw_apis():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    tdh = ctypes.WinDLL("tdh", use_last_error=True)

    trace_handle = ctypes.c_ulonglong
    advapi.StartTraceW.argtypes = [
        ctypes.POINTER(trace_handle),
        wintypes.LPCWSTR,
        ctypes.POINTER(EVENT_TRACE_PROPERTIES),
    ]
    advapi.StartTraceW.restype = wintypes.ULONG
    advapi.ControlTraceW.argtypes = [
        trace_handle,
        wintypes.LPCWSTR,
        ctypes.POINTER(EVENT_TRACE_PROPERTIES),
        wintypes.ULONG,
    ]
    advapi.ControlTraceW.restype = wintypes.ULONG
    advapi.EnableTraceEx2.argtypes = [
        trace_handle,
        ctypes.POINTER(GUID),
        wintypes.ULONG,
        ctypes.c_ubyte,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        wintypes.ULONG,
        ctypes.c_void_p,
    ]
    advapi.EnableTraceEx2.restype = wintypes.ULONG
    advapi.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
    advapi.OpenTraceW.restype = trace_handle
    advapi.ProcessTrace.argtypes = [
        ctypes.POINTER(trace_handle),
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi.ProcessTrace.restype = wintypes.ULONG
    advapi.CloseTrace.argtypes = [trace_handle]
    advapi.CloseTrace.restype = wintypes.ULONG

    tdh.TdhGetPropertySize.argtypes = [
        ctypes.POINTER(EVENT_RECORD),
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
        ctypes.POINTER(wintypes.ULONG),
    ]
    tdh.TdhGetPropertySize.restype = wintypes.ULONG
    tdh.TdhGetProperty.argtypes = [
        ctypes.POINTER(EVENT_RECORD),
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
        wintypes.ULONG,
        ctypes.c_void_p,
    ]
    tdh.TdhGetProperty.restype = wintypes.ULONG
    return advapi, tdh, trace_handle


def _configure_ip_helper():
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    iphlpapi.GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD
    return iphlpapi


def _new_properties():
    name_bytes = (len(SESSION_NAME) + 1) * ctypes.sizeof(wintypes.WCHAR)
    size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + name_bytes
    buffer = ctypes.create_string_buffer(size)
    props = ctypes.cast(buffer, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
    props.contents.Wnode.BufferSize = size
    props.contents.Wnode.Guid = _guid(str(uuid.uuid4()))
    props.contents.Wnode.ClientContext = 1
    props.contents.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    props.contents.BufferSize = 64
    props.contents.MinimumBuffers = 8
    props.contents.MaximumBuffers = 64
    props.contents.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
    props.contents.FlushTimer = 1
    props.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buffer, props


def _bytes_to_int(raw):
    if not raw:
        return None
    return int.from_bytes(raw, "little", signed=False)


def _bytes_to_port(raw):
    if len(raw) < 2:
        return None
    little = int.from_bytes(raw[:2], "little", signed=False)
    if 1 <= little <= 65535:
        return little
    big = int.from_bytes(raw[:2], "big", signed=False)
    return big if 1 <= big <= 65535 else None


def _port_from_dword(value):
    return socket.ntohs(int(value) & 0xFFFF)


def _bytes_to_ip(raw):
    if len(raw) >= 16:
        try:
            return str(ipaddress.IPv6Address(raw[:16]))
        except ValueError:
            return None
    if len(raw) >= 4:
        try:
            return socket.inet_ntoa(raw[:4])
        except OSError:
            return None
    return None


def _local_ips():
    ips = set()
    if not psutil:
        return ips
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(addr.address.split("%", 1)[0])
    except Exception:
        logger.debug("Failed to enumerate local IPs", exc_info=True)
    return ips


def _is_noise_ip(ip_value, local_ip_set):
    try:
        parsed = ipaddress.ip_address(ip_value)
    except ValueError:
        return True
    return (
        ip_value in local_ip_set
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_link_local
        or parsed.is_private
    )


class UdpOwnerMap:
    """Maps local UDP ports to owning PIDs using Windows IP Helper."""

    def __init__(self):
        self.iphlpapi = None
        self.pid_ports = {}
        self.port_pids = {}
        self.last_refresh = 0

    def refresh(self, max_age=2.0):
        now = time.monotonic()
        if now - self.last_refresh < max_age:
            return
        self.last_refresh = now
        if os.name != "nt":
            return
        if self.iphlpapi is None:
            self.iphlpapi = _configure_ip_helper()

        pid_ports = {}
        port_pids = {}
        for family, row_type in (
            (AF_INET, MIB_UDPROW_OWNER_PID),
            (AF_INET6, MIB_UDP6ROW_OWNER_PID),
        ):
            try:
                self._read_family(family, row_type, pid_ports, port_pids)
            except Exception:
                logger.debug("Failed to read UDP owner table for family %s", family, exc_info=True)

        self.pid_ports = pid_ports
        self.port_pids = port_pids

    def _read_family(self, family, row_type, pid_ports, port_pids):
        size = wintypes.ULONG(0)
        status = self.iphlpapi.GetExtendedUdpTable(
            None,
            ctypes.byref(size),
            False,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        )
        if status != ERROR_INSUFFICIENT_BUFFER or size.value == 0:
            return

        buffer = ctypes.create_string_buffer(size.value)
        status = self.iphlpapi.GetExtendedUdpTable(
            buffer,
            ctypes.byref(size),
            False,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        )
        if status != ERROR_SUCCESS:
            return

        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        offset = ctypes.sizeof(wintypes.DWORD)
        for index in range(count):
            row = row_type.from_buffer_copy(buffer, offset + index * ctypes.sizeof(row_type))
            pid = int(row.dwOwningPid)
            port = _port_from_dword(row.dwLocalPort)
            if pid <= 0 or port <= 0:
                continue
            pid_ports.setdefault(pid, set()).add(port)
            port_pids.setdefault(port, set()).add(pid)

    def ports_for_pids(self, pids):
        self.refresh()
        ports = set()
        for pid in pids:
            ports.update(self.pid_ports.get(int(pid), set()))
        return ports

    def pids_for_port(self, port):
        self.refresh()
        return set(self.port_pids.get(int(port), set()))


class EtwFlowCollector:
    """Collects recent UDP flow telemetry and selects highest-throughput flows."""

    def __init__(self, window_seconds=WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.activity_event = threading.Event()
        self.tracked_pids = set()
        self.flows = {}
        self.running = False
        self.available = False
        self.status_message = "ETW flow telemetry not started"
        self.local_ips = set()
        self.owner_map = UdpOwnerMap()
        self.advapi = None
        self.tdh = None
        self.trace_handle_type = None
        self.session_handle = None
        self.consumer_handle = None
        self.props_buffer = None
        self.props = None
        self.callback = None
        self.thread = None
        self.logfile = None

    def start(self):
        if os.name != "nt":
            self.status_message = "ETW flow telemetry is Windows-only"
            logger.info(self.status_message)
            return False
        try:
            self.advapi, self.tdh, self.trace_handle_type = _configure_etw_apis()
            self.local_ips = _local_ips()
            self.owner_map.refresh(max_age=0)
            self._start_session()
            self._open_consumer()
            self.running = True
            self.thread = threading.Thread(target=self._process, name="MultiWANQoSETW", daemon=True)
            self.thread.start()
            self.available = True
            self.status_message = "ETW flow telemetry active"
            logger.info(self.status_message)
            return True
        except OSError as exc:
            code = exc.errno if isinstance(exc.errno, int) else ctypes.get_last_error()
            if code == 5:
                self.status_message = "ETW flow telemetry needs administrator rights"
                logger.warning(self.status_message)
            else:
                self.status_message = f"ETW flow telemetry unavailable ({code})"
                logger.exception("Failed to start ETW flow telemetry")
            self.stop()
            return False
        except Exception:
            self.status_message = "ETW flow telemetry failed to start"
            logger.exception("Failed to start ETW flow telemetry")
            self.stop()
            return False

    def stop(self):
        self.running = False
        try:
            if self.advapi and self.consumer_handle:
                self.advapi.CloseTrace(self.consumer_handle)
        except Exception:
            logger.debug("CloseTrace failed", exc_info=True)
        try:
            if self.advapi and self.session_handle is not None and self.props:
                self.advapi.ControlTraceW(
                    self.session_handle,
                    SESSION_NAME,
                    self.props,
                    EVENT_TRACE_CONTROL_STOP,
                )
        except Exception:
            logger.debug("ControlTrace stop failed", exc_info=True)
        self.available = False

    def status(self):
        return {
            "available": self.available,
            "message": self.status_message,
        }

    def consume_activity(self):
        """Consume the new-flow wake signal used by the monitor safety loop."""
        if not self.activity_event.is_set():
            return False
        self.activity_event.clear()
        return True

    def set_tracked_pids(self, pids):
        """Limit monitor wakeups to flows owned by currently detected games."""
        with self.lock:
            self.tracked_pids = {int(pid) for pid in pids}

    def _start_session(self):
        self.props_buffer, self.props = _new_properties()
        self.session_handle = self.trace_handle_type()
        status = self.advapi.StartTraceW(
            ctypes.byref(self.session_handle),
            SESSION_NAME,
            self.props,
        )
        if status == ERROR_ALREADY_EXISTS:
            old_handle = self.trace_handle_type()
            self.advapi.ControlTraceW(old_handle, SESSION_NAME, self.props, EVENT_TRACE_CONTROL_STOP)
            status = self.advapi.StartTraceW(
                ctypes.byref(self.session_handle),
                SESSION_NAME,
                self.props,
            )
        if status != ERROR_SUCCESS:
            raise OSError(status, "StartTraceW failed")

        provider_guid = _guid(KERNEL_NETWORK_GUID)
        status = self.advapi.EnableTraceEx2(
            self.session_handle,
            ctypes.byref(provider_guid),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            KERNEL_NETWORK_KEYWORDS,
            0,
            0,
            None,
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "EnableTraceEx2 failed")

    def _open_consumer(self):
        self.callback = EVENT_RECORD_CALLBACK(self._on_event)
        self.logfile = EVENT_TRACE_LOGFILEW()
        self.logfile.LoggerName = SESSION_NAME
        self.logfile.ProcessTraceMode = (
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        )
        self.logfile.EventRecordCallback = self.callback
        self.consumer_handle = self.advapi.OpenTraceW(ctypes.byref(self.logfile))
        if self.consumer_handle == INVALID_PROCESSTRACE_HANDLE:
            raise OSError(ctypes.get_last_error(), "OpenTraceW failed")

    def _process(self):
        handle = self.trace_handle_type(self.consumer_handle)
        status = self.advapi.ProcessTrace(ctypes.byref(handle), 1, None, None)
        if self.running and status != ERROR_SUCCESS:
            self.status_message = f"ETW flow telemetry stopped ({status})"
            logger.warning("ETW ProcessTrace exited with status %s", status)

    def _property_raw(self, event_record, *names):
        for name in names:
            name_buffer = ctypes.create_unicode_buffer(name)
            descriptor = PROPERTY_DATA_DESCRIPTOR(
                ctypes.cast(name_buffer, ctypes.c_void_p).value,
                0xFFFFFFFF,
                0,
            )
            size = wintypes.ULONG(0)
            status = self.tdh.TdhGetPropertySize(
                event_record,
                0,
                None,
                1,
                ctypes.byref(descriptor),
                ctypes.byref(size),
            )
            if status != ERROR_SUCCESS or size.value == 0:
                continue
            data = ctypes.create_string_buffer(size.value)
            status = self.tdh.TdhGetProperty(
                event_record,
                0,
                None,
                1,
                ctypes.byref(descriptor),
                size.value,
                data,
            )
            if status == ERROR_SUCCESS:
                return data.raw
        return None

    def _on_event(self, event_record):
        try:
            header = event_record.contents.EventHeader
            event_id = int(header.EventDescriptor.Id)
            if event_id not in UDP_EVENT_IDS:
                return

            pid = _bytes_to_int(
                self._property_raw(event_record, "PID", "ProcessId", "ProcessID") or b""
            )
            size = _bytes_to_int(
                self._property_raw(event_record, "size", "Size", "TransferSize") or b""
            )
            saddr = _bytes_to_ip(
                self._property_raw(event_record, "saddr", "SAddr", "SourceAddress") or b""
            )
            daddr = _bytes_to_ip(
                self._property_raw(event_record, "daddr", "DAddr", "DestinationAddress") or b""
            )
            sport = _bytes_to_port(
                self._property_raw(event_record, "sport", "SPort", "SourcePort") or b""
            )
            dport = _bytes_to_port(
                self._property_raw(event_record, "dport", "DPort", "DestinationPort") or b""
            )

            if not pid:
                pid = int(header.ProcessId)
            if not (size and saddr and daddr and sport and dport):
                return

            self.record(pid, event_id, size, saddr, sport, daddr, dport)
        except Exception:
            logger.debug("Failed to process ETW UDP event", exc_info=True)

    def record(self, pid, event_id, size, saddr, sport, daddr, dport):
        now = time.monotonic()
        remote_ip = None
        remote_port = None
        local_port = None
        candidate_pid = int(pid) if pid else 0

        self.owner_map.refresh()
        sport_owners = self.owner_map.pids_for_port(sport) if sport else set()
        dport_owners = self.owner_map.pids_for_port(dport) if dport else set()

        # Prefer the Windows UDP owner table over ETW field ordering. Some game
        # UDP sockets are unconnected and some ETW templates expose local/remote
        # values in a provider-specific order; the owned port is the PC-side
        # local port, so the opposite port is the server port we need for nft/QoS.
        if candidate_pid and candidate_pid in sport_owners and candidate_pid not in dport_owners:
            local_port = sport
            remote_ip, remote_port = daddr, dport
        elif candidate_pid and candidate_pid in dport_owners and candidate_pid not in sport_owners:
            local_port = dport
            remote_ip, remote_port = saddr, sport
        elif sport_owners and not dport_owners:
            local_port = sport
            remote_ip, remote_port = daddr, dport
        elif dport_owners and not sport_owners:
            local_port = dport
            remote_ip, remote_port = saddr, sport

        if not remote_ip and saddr in self.local_ips and daddr not in self.local_ips:
            local_port = sport
            remote_ip, remote_port = daddr, dport
        elif not remote_ip and daddr in self.local_ips and saddr not in self.local_ips:
            local_port = dport
            remote_ip, remote_port = saddr, sport
        elif not remote_ip and event_id in SEND_EVENT_IDS:
            local_port = sport
            remote_ip, remote_port = daddr, dport
        elif not remote_ip and event_id in RECV_EVENT_IDS:
            local_port = dport
            remote_ip, remote_port = saddr, sport

        if not remote_ip or not remote_port:
            return
        if remote_port in IGNORED_UDP_PORTS:
            return
        if _is_noise_ip(remote_ip, self.local_ips):
            return

        owner_pids = self.owner_map.pids_for_port(local_port) if local_port else set()
        candidate_pids = {int(pid)} if pid else set()
        candidate_pids.update(owner_pids)
        if not candidate_pids:
            return

        with self.lock:
            tracked_pids = set(self.tracked_pids)
            for candidate_pid in candidate_pids:
                local_port_id = int(local_port or 0)
                key = (candidate_pid, remote_ip, int(remote_port), local_port_id)
                if local_port_id:
                    stale_keys = [
                        old_key for old_key in self.flows
                        if len(old_key) == 4
                        and old_key[0] == candidate_pid
                        and old_key[1] == remote_ip
                        and old_key[2] == int(remote_port)
                        and old_key[3] != local_port_id
                    ]
                    for old_key in stale_keys:
                        del self.flows[old_key]
                flow = self.flows.get(key)
                if not flow:
                    flow = {
                        "pid": candidate_pid,
                        "remote_ip": remote_ip,
                        "remote_port": int(remote_port),
                        "local_port": local_port_id,
                        "bytes": 0,
                        "packets": 0,
                        "first_seen": now,
                        "last_seen": now,
                    }
                    self.flows[key] = flow
                    if candidate_pid in tracked_pids:
                        self.activity_event.set()
                flow["bytes"] += int(size)
                flow["packets"] += 1
                flow["last_seen"] = now
            self._prune_locked(now)

    def _prune_locked(self, now):
        cutoff = now - self.window_seconds
        stale = [
            key
            for key, flow in self.flows.items()
            if flow["last_seen"] < cutoff
        ]
        for key in stale:
            del self.flows[key]

    def select_for_pids(
        self,
        pids,
        min_age=MIN_FLOW_AGE,
        stale_seconds=STALE_SECONDS,
        min_bps=MIN_BYTES_PER_SECOND,
        top_ratio=TOP_FLOW_RATIO,
        max_flows=MAX_SELECTED_FLOWS,
    ):
        now = time.monotonic()
        pid_set = {int(pid) for pid in pids}
        selected = []
        ignored = []

        with self.lock:
            self._prune_locked(now)
            candidates = [
                dict(flow)
                for flow in self.flows.values()
                if flow["pid"] in pid_set
            ]

        ranked = []
        for flow in candidates:
            age = max(flow["last_seen"] - flow["first_seen"], 0.001)
            idle = now - flow["last_seen"]
            bps = flow["bytes"] / age
            flow["bytes_per_sec"] = bps
            flow["age"] = age
            flow["idle"] = idle

            if age < min_age:
                flow["ignored_reason"] = "warming up"
                ignored.append(flow)
            elif idle > stale_seconds:
                flow["ignored_reason"] = "stale"
                ignored.append(flow)
            elif bps < min_bps:
                flow["ignored_reason"] = "low throughput"
                ignored.append(flow)
            else:
                ranked.append(flow)

        ranked.sort(key=lambda item: item["bytes_per_sec"], reverse=True)
        if not ranked:
            return [], ignored

        top_bps = ranked[0]["bytes_per_sec"]
        for flow in ranked:
            if len(selected) >= max_flows:
                flow["ignored_reason"] = "over cap"
                ignored.append(flow)
                continue
            if selected and flow["bytes_per_sec"] < (top_bps * top_ratio):
                flow["ignored_reason"] = "below top flow ratio"
                ignored.append(flow)
                continue
            flow["selected"] = True
            flow["source"] = "ETW flow telemetry"
            selected.append(flow)

        return selected, ignored
