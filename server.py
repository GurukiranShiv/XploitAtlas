"""Authenticated WSGI application served by the bundled Waitress server."""
from __future__ import annotations
import argparse
import logging
import sys
from config import ROOT,VERSION,environment,load_environment,public_origin,setting


def parser():
    result=argparse.ArgumentParser(description='Run the MasterMonk OSINT explorer with optional authenticated tools.')
    result.add_argument('--host')
    result.add_argument('--port',type=int)
    result.add_argument('--data-dir')
    result.add_argument('--base-url')
    result.add_argument('--sync-mode',choices=['embedded','external','off'])
    result.add_argument('--no-sync',action='store_true',help='Serve saved records without starting collectors.')
    result.add_argument('--public-catalog',action='store_true',help='Allow anonymous access to public intelligence; inventories remain private.')
    return result


def main(argv=None):
    load_environment()
    args=parser().parse_args(argv)
    config=environment()
    for key in ('host','port','sync_mode'):
        if getattr(args,key) is not None:
            config[key]=getattr(args,key)
    if args.no_sync:
        config['sync_mode']='off'
    if args.base_url:
        config['origin']=public_origin(args.base_url)
        from urllib.parse import urlsplit
        config['hosts'].add(urlsplit(config['origin']).hostname)
        config['secure']=config['origin'].startswith('https://')
    config['public_catalog'] |= args.public_catalog
    if config['sync_mode'] not in {'embedded','external','off'}:
        raise ValueError('MASTERMONK_SYNC_MODE must be embedded, external, or off.')
    if not 1<=config['port']<=65535:
        raise ValueError('Choose a port between 1 and 65535.')
    if config['host'] not in {'localhost','127.0.0.1','::1'} and not config['origin']:
        raise ValueError('Set MASTERMONK_BASE_URL before binding externally: use your public HTTPS address, or an explicit localhost address for a local container.')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    sys.path.insert(0,str(ROOT/'_vendor'))
    from waitress import create_server
    from services import Services
    from webapp import Application
    services=Services(args.data_dir)
    application=Application(services,config)
    options=dict(host=config['host'],port=config['port'],threads=8,connection_limit=128,
                 channel_timeout=60,max_request_body_size=9*1024*1024,max_request_header_size=32768,
                 ident='MasterMonk',clear_untrusted_proxy_headers=True)
    proxy=setting('TRUSTED_PROXY')
    if proxy:
        if proxy=='*':
            raise ValueError('Use the explicit IP address of your reverse proxy, not a wildcard.')
        options.update(trusted_proxy=proxy,trusted_proxy_count=1,
                       trusted_proxy_headers={'x-forwarded-for','x-forwarded-proto'})
    httpd=None
    try:
        httpd=create_server(application,**options)
        if config['sync_mode']=='embedded':
            services.start_worker()
        address=config['origin'] or 'http://'+('['+config['host']+']' if ':' in config['host'] else config['host'])+':'+str(config['port'])
        print(f'MasterMonk {VERSION} | {address}',flush=True)
        print(f'Data: {services.path} | Collector: {config["sync_mode"]}',flush=True)
        if application.setup_code:
            print('Open Discover to browse and learn. Administration is optional.',flush=True)
            print('Use the code below only when setting up administration.',flush=True)
            print('First-run setup code (expires after 30 minutes): '+application.setup_code,flush=True)
        print('Press Ctrl+C to stop.',flush=True)
        httpd.run()
    except KeyboardInterrupt:
        pass
    finally:
        if httpd:
            httpd.close()
        services.close()
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,RuntimeError) as exc:
        print('MasterMonk: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
