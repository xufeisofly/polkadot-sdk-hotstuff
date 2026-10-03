#!/usr/bin/env python3
"""Real local Wasm nodes: quorum, sessions, restart, full sync and warp sync."""
import json
import datetime
import platform
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'target/debug/solochain-template-node'
RUN = ROOT / 'artifacts/network'
NAMES = ['alice', 'bob', 'charlie', 'dave', 'observer', 'warp']
BASE_RPC, BASE_P2P = 19940, 30940
processes, handles, peers = {}, {}, {}
report = {'success': False, 'platform': platform.platform(), 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': []}


def rpc(i, method, params=None):
    data = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    req = urllib.request.Request('http://127.0.0.1:%d' % (BASE_RPC+i), data, {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=4) as response:
        result = json.load(response)
    if 'error' in result:
        raise RuntimeError(result['error'])
    return result['result']


def finalized(i):
    h = rpc(i, 'chain_getFinalizedHead')
    return int(rpc(i, 'chain_getHeader', [h])['number'], 16)


def wait_for(label, check, timeout=180):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        for i, proc in processes.items():
            if proc.poll() is not None:
                raise RuntimeError('%s exited %s; see %s.log' % (NAMES[i], proc.returncode, NAMES[i]))
        try:
            value = check()
            if value:
                print(label + ': ' + str(value), flush=True)
                report['checks'].append({'name': label, 'result': value})
                return value
        except (OSError, ValueError, RuntimeError) as error:
            last = str(error)
        time.sleep(1)
    raise AssertionError('%s timed out; last error: %s' % (label, last))


def start(i, warp=False):
    name = NAMES[i]
    args = [str(BIN), '--chain', 'local', '--base-path', str(RUN/'data'/name),
            '--name', name, '--rpc-port', str(BASE_RPC+i),
            '--listen-addr', '/ip4/127.0.0.1/tcp/%d' % (BASE_P2P+i),
            '--public-addr', '/ip4/127.0.0.1/tcp/%d' % (BASE_P2P+i),
            '--node-key', '%064x' % (i+1), '--no-mdns', '--discover-local', '--allow-private-ip',
            '--no-telemetry', '--no-prometheus', '--database', 'paritydb',
            '--state-pruning', '256' if warp else 'archive', '--blocks-pruning', 'archive',
            '--sync', 'warp' if warp else 'full', '--rpc-methods', 'Safe',
            '--log', 'info,sc-consensus-hotstuff=trace']
    if i < 4:
        args.append('--'+name)
    for j, peer in peers.items():
        if j != i and j in processes:
            args.extend(['--bootnodes', '/ip4/127.0.0.1/tcp/%d/p2p/%s' % (BASE_P2P+j, peer)])
    handles[i] = (RUN/(name+'.log')).open('a')
    env = os.environ.copy()
    env['RUST_LOG'] = 'info'
    processes[i] = subprocess.Popen(args, cwd=ROOT, stdout=handles[i], stderr=subprocess.STDOUT, env=env)
    peers[i] = wait_for(name+' RPC ready', lambda: rpc(i, 'system_localPeerId'), 120)


def stop(i):
    p = processes.pop(i)
    p.terminate()
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)
    handles.pop(i).close()


def progress(ids, floor):
    heights = [finalized(i) for i in ids]
    return heights if min(heights) >= floor else False


def agree(ids):
    height = min(finalized(i) for i in ids)
    hashes = [rpc(i, 'chain_getBlockHash', [height]) for i in ids]
    assert len(set(hashes)) == 1, ('conflicting finality', height, hashes)
    return {'height': height, 'hash': hashes[0], 'nodes': list(ids)}


def main():
    if (RUN/'data').exists():
        raise SystemExit('Existing test data found; move/remove artifacts/network/data before another run.')
    for port in [BASE_RPC+i for i in range(6)] + [BASE_P2P+i for i in range(6)]:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    RUN.mkdir(parents=True, exist_ok=True)
    try:
        start(0)
        start(1)
        time.sleep(6)
        assert [finalized(0), finalized(1)] == [0, 0], 'two of four must not finalize'
        report['checks'].append({'name': 'two of four cannot start', 'result': True})
        start(2)
        wait_for('three of four finalizing', lambda: progress(range(3), 12))
        start(3)
        wait_for('four validators cross three sessions', lambda: progress(range(4), 125), 600)
        report['checks'].append({'name': 'four validators agree', 'result': agree(range(4))})
        stop(3)
        floor = finalized(0)+15
        wait_for('one offline retains finality', lambda: progress(range(3), floor))
        stop(2)
        time.sleep(8)
        before = finalized(0)
        time.sleep(6)
        assert finalized(0) == before, 'two of four must stall finality'
        report['checks'].append({'name': 'two of four stall finality', 'result': before})
        start(2)
        wait_for('restart restores quorum', lambda: progress(range(3), before+15))
        start(3)
        floor = finalized(0)+10
        wait_for('restarted validator catches up', lambda: progress(range(4), floor))
        start(4)
        wait_for('fresh full node syncs', lambda: progress([4], floor))
        floor = finalized(0)
        start(5, warp=True)
        wait_for('fresh warp node syncs', lambda: progress([5], floor), 240)
        floor = finalized(0)+10
        wait_for('all nodes follow live blocks', lambda: progress(range(6), floor))
        report['checks'].append({'name': 'all nodes agree on finalized hash', 'result': agree(range(6))})
        report['success'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for i in list(processes):
            stop(i)
        (ROOT/'artifacts/network-results.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
