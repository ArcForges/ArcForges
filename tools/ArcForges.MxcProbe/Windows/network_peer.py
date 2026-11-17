# SPDX-License-Identifier: AGPL-3.0-only
import hashlib, ipaddress, json, os, pathlib, pwd, re, selectors, socket, subprocess, sys, time
VERSION = 1
SCRIPT_PATH = pathlib.Path(__file__).resolve()
SOURCE_SHA256 = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
SOURCE_COMMIT = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == '--source-commit' else ''
PEER_HOST = socket.gethostname()
PEER_UID = os.geteuid()
PEER_USER = pwd.getpwuid(PEER_UID).pw_name
os.umask(0o077)
DEADLINE_SECONDS = 240
SENTINEL = b'AFV2_NET_SENTINEL\n'
counts = dict(tcpAccepted=0, tcpMatched=0, udpReceived=0, udpMatched=0, otherTcpAccepted=0, otherTcpMatched=0)
selector = selectors.DefaultSelector()
owned = []
clients = {}
error_code = None
stop = False
control_buffer = bytearray()
# This experiment uses the host's existing global IPv6 route. No address or
# route is installed, and an absent prerequisite never falls back to IPv4.
ADDRESS_SOURCE = 'default_route_assigned_global_ipv6'
interface_name = None
route_candidate_count = 0
address_candidate_count = 0
phase = 'source_admission'
error_phase = exception_type = native_errno = script_line = None

def emit(kind, **fields):
    value = dict(kind=kind, protocolVersion=VERSION, sourceSha256=SOURCE_SHA256,
                 sourceCommit=SOURCE_COMMIT, peerHost=PEER_HOST, peerUid=PEER_UID, peerUser=PEER_USER,
                 addressSource=ADDRESS_SOURCE, interfaceName=interface_name,
                 defaultInterfaceCandidateCount=route_candidate_count, addressCandidateCount=address_candidate_count)
    value.update(fields)
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()

def snapshot(kind, **fields):
    emit(kind, **counts, peerHealthy=error_code is None, errorCode=error_code, errorPhase=error_phase,
         exceptionType=exception_type, nativeErrno=native_errno, scriptLine=script_line, **fields)

def record_exception(issue):
    global error_phase, exception_type, native_errno, script_line
    for _ in range(4):
        if issue.__cause__ is None:
            break
        issue = issue.__cause__
    error_phase = phase
    exception_type = type(issue).__name__
    number = getattr(issue, 'errno', None)
    native_errno = number if isinstance(number, int) and -2147483648 <= number <= 2147483647 else None
    trace = issue.__traceback__
    script_line = None
    while trace is not None:
        if trace.tb_frame.f_code.co_filename == __file__:
            script_line = trace.tb_lineno
        trace = trace.tb_next

def close_client(connection):
    clients.pop(connection, None)
    try:
        selector.unregister(connection)
    except KeyError:
        pass
    connection.close()

def query_ip(arguments, phase):
    try:
        result = subprocess.run(['ip', '-j', '-6'] + arguments, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False)
    except FileNotFoundError as issue:
        raise ValueError('iproute_unavailable') from issue
    except subprocess.TimeoutExpired as issue:
        raise ValueError(phase + '_query_timeout') from issue
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError(phase + '_query_failed')
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError) as issue:
        raise ValueError(phase + '_json_invalid') from issue
    if not isinstance(value, list):
        raise ValueError(phase + '_json_invalid')
    return value

def query_git(root, arguments):
    result = subprocess.run(['/usr/bin/git', '--no-optional-locks', '-C', str(root)] + arguments,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=3, check=False)
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError('source_git_query_failed')
    return result.stdout

try:
    if not re.fullmatch('[0-9a-f]{40}', SOURCE_COMMIT):
        raise ValueError('source_commit_invalid')
    if PEER_HOST != 'v2202601329473427941' or PEER_UID != 1000 or PEER_USER != 'sammiller':
        raise ValueError('designated_host_identity_mismatch')
    root = pathlib.Path('/home/sammiller/arcforges/ArcForges/.worktree/mxc02-peer-' + SOURCE_COMMIT)
    relative_script = 'tools/ArcForges.MxcProbe/Windows/network_peer.py'
    if SCRIPT_PATH != root / relative_script:
        raise ValueError('source_worktree_path_mismatch')
    if query_git(root, ['remote', 'get-url', 'origin']).strip() != b'https://github.com/ArcForges/ArcForges.git':
        raise ValueError('source_origin_mismatch')
    if query_git(root, ['rev-parse', 'HEAD']).decode('ascii').strip() != SOURCE_COMMIT:
        raise ValueError('source_head_mismatch')
    recorded_script = query_git(root, ['show', SOURCE_COMMIT + ':' + relative_script])
    if hashlib.sha256(recorded_script).hexdigest() != SOURCE_SHA256:
        raise ValueError('source_script_modified')
    phase = 'setup_default_route'
    routes = query_ip(['route', 'show', 'default'], 'default_route')
    devices = {item.get('dev') for item in routes if isinstance(item, dict) and isinstance(item.get('dev'), str)}
    route_candidate_count = len(devices)
    if route_candidate_count != 1:
        raise ValueError('default_route_interface_not_unique')
    interface_name = next(iter(devices))
    if not 1 <= len(interface_name) <= 64 or not all(character.isascii() and (character.isalnum() or character in '-_.:@') for character in interface_name):
        raise ValueError('interface_name_invalid')
    phase = 'setup_interface_address'
    assigned = query_ip(['address', 'show', 'dev', interface_name, 'scope', 'global'], 'interface_address')
    phase = 'setup_address_selection'
    candidates = set()
    for item in assigned:
        if not isinstance(item, dict) or item.get('ifname') != interface_name:
            continue
        for entry in item.get('addr_info', []):
            if isinstance(entry, dict) and entry.get('family') == 'inet6' and entry.get('scope') == 'global':
                try:
                    candidate = ipaddress.IPv6Address(entry.get('local', ''))
                except ipaddress.AddressValueError as issue:
                    raise ValueError('assigned_ipv6_invalid') from issue
                if not candidate.is_global or candidate.is_loopback or candidate.is_unspecified or candidate.is_multicast:
                    raise ValueError('assigned_ipv6_invalid')
                candidates.add(str(candidate))
    address_candidate_count = len(candidates)
    if address_candidate_count != 1:
        raise ValueError('assigned_ipv6_not_unique')
    address = next(iter(candidates))
    phase = 'bind_tcp_udp'
    tcp = udp = None
    last_bind_error = None
    for attempt in range(8):
        tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tcp.bind((address, 0))
            port = tcp.getsockname()[1]
            udp.bind((address, port))
            break
        except OSError as issue:
            last_bind_error = issue
            tcp.close()
            udp.close()
            tcp = udp = None
    if tcp is None:
        raise OSError('matching_ports_unavailable') from last_bind_error
    owned.extend((tcp, udp))
    other = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    owned.append(other)
    phase = 'bind_other_tcp'
    other.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    other.bind((address, 0))
    other_port = other.getsockname()[1]
    phase = 'register_io'
    for listener, role in ((tcp, 'tcp'), (other, 'other')):
        listener.listen(16)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, role)
    udp.setblocking(False)
    selector.register(udp, selectors.EVENT_READ, 'udp')
    os.set_blocking(0, False)
    selector.register(0, selectors.EVENT_READ, 'control')
    end = time.monotonic() + DEADLINE_SECONDS
    emit('ready', peerProcessId=os.getpid(), address=str(address), port=port, otherTcpPort=other_port, deadlineSeconds=DEADLINE_SECONDS)
    while not stop and time.monotonic() < end:
        phase = 'select_io'
        for key, mask in selector.select(min(0.25, max(0, end-time.monotonic()))):
            role = key.data
            if role == 'control':
                phase = 'control'
                incoming = os.read(0, 256)
                if not incoming:
                    stop = True
                    break
                control_buffer.extend(incoming)
                if len(control_buffer) > 256:
                    raise ValueError('control_bound_exceeded')
                while b'\n' in control_buffer:
                    command, _, rest = control_buffer.partition(b'\n')
                    control_buffer[:] = rest
                    if command == b'snapshot':
                        snapshot('snapshot')
                    elif command == b'close':
                        stop = True
                        break
                    else:
                        raise ValueError('unknown_control')
            elif role in ('tcp', 'other'):
                phase = 'accept_tcp'
                connection, _ = key.fileobj.accept()
                counts['tcpAccepted' if role == 'tcp' else 'otherTcpAccepted'] += 1
                if len(clients) >= 32:
                    connection.close()
                    continue
                connection.setblocking(False)
                clients[connection] = dict(role=role, data=bytearray(), reply=None, sent=0, end=time.monotonic()+3)
                selector.register(connection, selectors.EVENT_READ, 'client')
            elif role == 'udp':
                phase = 'receive_udp'
                data, remote = udp.recvfrom(len(SENTINEL)+1)
                counts['udpReceived'] += 1
                if data == SENTINEL:
                    counts['udpMatched'] += 1
                    udp.sendto(SENTINEL, remote)
            else:
                connection = key.fileobj
                state = clients[connection]
                try:
                    if mask & selectors.EVENT_READ:
                        phase = 'client_read'
                        data = connection.recv(len(SENTINEL)+1-len(state['data']))
                        if not data:
                            close_client(connection)
                            continue
                        state['data'].extend(data)
                        if bytes(state['data']) == SENTINEL:
                            counts['tcpMatched' if state['role'] == 'tcp' else 'otherTcpMatched'] += 1
                            state['reply'] = SENTINEL
                            selector.modify(connection, selectors.EVENT_WRITE, 'client')
                        elif len(state['data']) >= len(SENTINEL):
                            close_client(connection)
                    elif mask & selectors.EVENT_WRITE:
                        phase = 'client_write'
                        state['sent'] += connection.send(state['reply'][state['sent']:])
                        if state['sent'] == len(SENTINEL):
                            close_client(connection)
                except (ConnectionError, OSError):
                    close_client(connection)
        phase = 'expire_clients'
        for connection, state in list(clients.items()):
            if time.monotonic() >= state['end']:
                close_client(connection)
    if not stop:
        error_code = 'hard_deadline_elapsed'
        error_phase = 'hard_deadline'
except ValueError as issue:
    record_exception(issue)
    known = {'source_commit_invalid', 'designated_host_identity_mismatch', 'source_worktree_path_mismatch',
             'source_origin_mismatch', 'source_head_mismatch', 'source_script_modified', 'source_git_query_failed',
             'default_route_query_failed', 'default_route_query_timeout', 'default_route_json_invalid',
             'interface_address_query_failed', 'interface_address_query_timeout', 'interface_address_json_invalid',
             'iproute_unavailable', 'default_route_interface_not_unique', 'interface_name_invalid',
             'assigned_ipv6_not_unique', 'assigned_ipv6_invalid', 'control_bound_exceeded', 'unknown_control'}
    error_code = str(issue) if str(issue) in known else 'peer_protocol_failed'
except subprocess.TimeoutExpired as issue:
    record_exception(issue)
    error_code = 'source_git_query_timeout'
except OSError as issue:
    record_exception(issue)
    error_code = 'peer_socket_failed'
except Exception as issue:
    record_exception(issue)
    error_code = 'peer_failed'
finally:
    for connection in list(clients):
        close_client(connection)
    for item in owned:
        item.close()
    selector.close()
    try:
        snapshot('closed', listenersClosed=True)
    except (BrokenPipeError, OSError):
        pass
