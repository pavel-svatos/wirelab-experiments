#!/usr/bin/env python3
"""Root-only isolated network test. Run via: sudo unshare --net python3 tests/integration.py.
Uses only newly created veth links and uniquely named network namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='build/magicboxd')
parser.add_argument('--web-root', default='web')
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit('Run as root inside a fresh network namespace using unshare --net')
if len(json.loads(subprocess.check_output(['ip', '-j', 'link']))) != 1:
    raise SystemExit('Refusing: test requires a fresh network namespace containing only loopback')
def run(*argv):
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, text=True, timeout=15)
inner, outer = f'mbx-test-in-{os.getpid()}', f'mbx-test-out-{os.getpid()}'
namespaces = []
process = None
servers = []
with tempfile.TemporaryDirectory(prefix='magicbox-test-') as directory:
    token = secrets.token_hex(32)
    token_file = Path(directory) / 'token'
    token_file.write_text(token)
    token_file.chmod(0o600)
    log = open(Path(directory) / 'daemon.log', 'w+')
    def api(path, method='GET', body=None, auth=True):
        req = urllib.request.Request('http://127.0.0.1:18080/api/v1/' + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Authorization': 'Bearer ' + token if auth else '', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    try:
        run('ip', 'link', 'set', 'lo', 'up')
        for ns in (inner, outer):
            run('ip', 'netns', 'add', ns); namespaces.append(ns)
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        for host, peer, ns in [('mbxin','device',inner), ('mbxout','upstream',outer)]:
            run('ip','link','add',host,'type','veth','peer','name',peer)
            run('ip','link','set',peer,'netns',ns)
            Path(f'/proc/sys/net/ipv6/conf/{host}/disable_ipv6').write_text('1')
            run('ip','-n',ns,'link','set',peer,'up')
        original_mac = json.loads(run('ip','-j','link','show','mbxout'))[0]['address']
        run('ip','-n',inner,'addr','add','10.0.0.5/24','dev','device')
        run('ip','-n',inner,'route','add','default','via','10.0.0.1')
        process = subprocess.Popen([str(Path(args.binary).resolve()), '--port','18080','--token-file',str(token_file),
            '--database',directory+'/db.sqlite','--web-root',str(Path(args.web_root).resolve()),'--allow-network'], stdout=log,stderr=log)
        for _ in range(100):
            try:
                api('status'); break
            except (OSError, urllib.error.URLError):
                if process.poll() is not None: raise RuntimeError('Daemon exited')
                time.sleep(.1)
        else: raise RuntimeError('Daemon startup timeout')
        try:
            api('status',auth=False)
            raise AssertionError('Unauthenticated request accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        assert b'WireLab Experiments' in urllib.request.urlopen('http://127.0.0.1:18080/').read()
        import websocket
        ws = websocket.create_connection('ws://127.0.0.1:18080/api/v1/live',timeout=5)
        ws.send(json.dumps({'token':token,'ack':'0'}))
        assert json.loads(ws.recv())['sequence'] == '1'
        ws.close()
        run('ip','link','set','mbxin','up')
        api('capture','PUT',{'interface':'mbxin'})
        for vlan in (None,100):
            upstream = 'upstream'
            if vlan:
                run('ip','-n',outer,'link','add','link','upstream','name','upstream.100','type','vlan','id','100')
                upstream = 'upstream.100'
                run('ip','-n',outer,'link','set',upstream,'up')
            run('ip','-n',outer,'addr','add','192.168.50.1/24','dev',upstream)
            config = dict(outer_interface='mbxout',inner_interface='mbxin',device_ipv4='10.0.0.5',inner_gateway_ipv4='10.0.0.1',
                inner_prefix=24,outer_ipv4='192.168.50.99',outer_prefix=24,outer_gateway_ipv4='192.168.50.1',outer_mac='02:11:22:33:44:55',vlan_id=vlan)
            assert api('config','PUT',config)['status'] == 'awaiting_confirmation'
            assert json.loads(run('ip','-j','link','show','mbxout'))[0]['address'] == config['outer_mac']
            run('ip','netns','exec',inner,'ping','-c','2','-W','2','192.168.50.1')
            run('ip','netns','exec',outer,'ping','-c','2','-W','2','192.168.50.99')
            # A protected-only TCP listener proves inbound DNAT reaches the device,
            # rather than merely receiving a ping reply from the appliance itself.
            listener = subprocess.Popen(['ip','netns','exec',inner,'python3','-u','-c',
                "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                "s.bind(('10.0.0.5',18081)); s.listen(1); print('ready',flush=True); "
                "c,a=s.accept(); c.recv(4096); c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: 16\\r\\n\\r\\nprotected-device'); c.close(); s.close()"], stdout=subprocess.PIPE,text=True)
            servers.append(listener)
            assert listener.stdout.readline().strip() == 'ready'
            response = run('ip','netns','exec',outer,'python3','-c',
                "import urllib.request; print(urllib.request.urlopen('http://192.168.50.99:18081/',timeout=3).read().decode())")
            assert response.strip() == 'protected-device'
            assert listener.wait(timeout=5) == 0
            if vlan:
                assert json.loads(run('ip','-d','-j','link','show','mbx-outer'))[0]['linkinfo']['info_data']['id'] == 100
            assert api('config/confirm','POST',{})['status'] == 'confirmed'
            time.sleep(1.1)
            assert int(api('metrics')['packets']) > 0
            assert len(api('packets')) > 0
            assert len(api('history')) > 0
            assert len(api('flows')) > 0
            assert api('config/rollback','POST',{})['status'] == 'inactive'
            assert json.loads(run('ip','-j','link','show','mbxout'))[0]['address'] == original_mac
            assert json.loads(run('ip','-j','addr','show','mbxin'))[0]['addr_info'] == []
            run('ip','-n',outer,'addr','del','192.168.50.1/24','dev',upstream)
            print(f'PASS: NAT in both directions, MAC, VLAN={vlan}, capture, history, rollback',flush=True)
        # Pending configuration must roll back after 60 seconds without confirmation.
        config['vlan_id'] = None
        api('config','PUT',config)
        deadline = time.monotonic()+70
        while api('config')['status'] != 'inactive':
            assert time.monotonic() < deadline, 'Confirmation timeout did not roll back'
            time.sleep(1)
        print('PASS: automatic confirmation-timeout rollback',flush=True)
        # Recover a crash during the confirmation window using the persisted journal.
        api('config','PUT',config)
        process.kill(); process.wait(timeout=5)
        process = subprocess.Popen([str(Path(args.binary).resolve()), '--port','18080','--token-file',str(token_file),
            '--database',directory+'/db.sqlite','--web-root',str(Path(args.web_root).resolve()),'--allow-network'], stdout=log,stderr=log)
        for _ in range(100):
            try:
                assert api('config')['status'] == 'inactive'; break
            except (OSError, urllib.error.URLError):
                if process.poll() is not None: raise RuntimeError('Recovery daemon exited')
                time.sleep(.1)
        else: raise RuntimeError('Recovery timeout')
        assert json.loads(run('ip','-j','link','show','mbxout'))[0]['address'] == original_mac
        print('PASS: crash recovery restores unconfirmed configuration',flush=True)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        print('PASS: graceful shutdown',flush=True)
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError): print(error.read().decode())
        log.flush(); log.seek(0); print(log.read())
        raise
    finally:
        for server in servers:
            if server.poll() is None: server.terminate(); server.wait(timeout=5)
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        for ns in namespaces:
            subprocess.run(['ip','netns','del',ns],check=False)
        log.close()
