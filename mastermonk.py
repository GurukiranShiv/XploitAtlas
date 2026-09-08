"""MasterMonk command line: serve, collect, check real dependencies, and export."""
from __future__ import annotations
import argparse
import getpass
import json
import logging
import signal
import sys
import tempfile
import threading
from contextlib import nullcontext
from pathlib import Path
from config import VERSION,load_environment
from core import now


def sarif(report,path):
    rules,results={},[]
    violating={(v['advisory'],v['package']['ecosystem'],v['package']['name'],v['package']['version']) for v in report['policy']['violations']}
    for check in report['checks']:
        component=check['component']
        for finding in check['findings']:
            identifier=finding['advisoryId']
            rules[identifier]={'id':identifier,'shortDescription':{'text':finding['title']},'helpUri':finding['url']}
            breach=(identifier,component['ecosystem'],component['name'],component['version']) in violating
            results.append({'ruleId':identifier,'level':'error' if breach else 'warning',
                'message':{'text':component['name']+'@'+component['version']+': '+finding['title']},
                'locations':[{'physicalLocation':{'artifactLocation':{'uri':Path(path).name}}}],
                'partialFingerprints':{'packageAdvisory':component['ecosystem']+':'+component['name']+'@'+component['version']+':'+identifier},
                'properties':{'kev':finding['kev'],'fixedVersions':finding['fixedVersions'],'evidence':finding['url']}})
    invocation={'executionSuccessful':report['policy']['complete'],'exitCode':report['policy']['exitCode']}
    if not report['policy']['complete']:
        invocation['toolExecutionNotifications']=[{'level':'error','message':{'text':'Coverage or an upstream query is incomplete; this run cannot establish a passing result.'}}]
    return {'$schema':'https://json.schemastore.org/sarif-2.1.0.json','version':'2.1.0','runs':[{
        'tool':{'driver':{'name':'MasterMonk','version':VERSION,'rules':list(rules.values())}},
        'invocations':[invocation],'results':results}]}


def check(args):
    from store import Store
    from feeds import Ingestor
    from manifests import parse_document
    from scanner import check_components,evaluate_policy
    path=Path(args.manifest).resolve()
    parsed=parse_document(path.name,path.read_text(encoding='utf-8-sig'))
    context=nullcontext(str(Path(args.data_dir).resolve())) if args.data_dir else tempfile.TemporaryDirectory(prefix='mastermonk-check-')
    with context as directory:
        root=Path(directory);root.mkdir(parents=True,exist_ok=True)
        catalog=Store(root/'mastermonk.sqlite3')
        ingestor=Ingestor(catalog,root)
        ingestor.sync(['cisa'])
        checks=check_components(ingestor.client,parsed['components'],catalog)
        policy=evaluate_policy(checks,catalog,args.fail_on,args.threshold,parsed['complete'])
        report={'application':'MasterMonk','version':VERSION,'observedAt':now(),'manifest':path.name,
                'coverage':parsed['coverage'],'warnings':parsed['warnings'],'policy':policy,'checks':checks,
                'sources':catalog.sources()}
        if args.format=='sarif':
            output=json.dumps(sarif(report,path),indent=2,ensure_ascii=False,allow_nan=False)
        elif args.format=='json':
            output=json.dumps(report,indent=2,ensure_ascii=False,allow_nan=False)
        else:
            lines=[f'MasterMonk | {path.name} | {len(checks)} components',
                   f'Policy: {args.fail_on} | '+('PASS' if policy['passed'] else 'INCOMPLETE' if not policy['complete'] else 'VIOLATIONS'),
                   parsed['coverage']]
            lines.extend(parsed['warnings'])
            for result in checks:
                component=result['component']
                for finding in result['findings']:
                    lines.append(f'{component["name"]}@{component["version"]} | {finding["advisoryId"]} | {finding["severity"]} | KEV={finding["kev"]} | {finding["url"]}')
                if not result['complete']:
                    lines.append(f'{component["name"]}: {result["error"] or "Query incomplete"}')
            lines.append(f'{len(policy["violations"])} policy violations. Exit code {policy["exitCode"]}.')
            output='\n'.join(lines)
        if args.output:
            target=Path(args.output);target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text(output+'\n',encoding='utf-8')
        else:
            print(output)
        ingestor.close()
        return policy['exitCode']


def main(argv=None):
    load_environment()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        from server import main as serve_main
        return serve_main(argv[1:])
    parser=argparse.ArgumentParser(description='MasterMonk: real-source vulnerability workflows.')
    parser.add_argument('--version',action='version',version=VERSION)
    commands=parser.add_subparsers(dest='command',required=True)
    serve=commands.add_parser('serve',help='Start the web application; use start.py --help for server options.')
    serve.add_argument('options',nargs=argparse.REMAINDER)
    for command,description in [('worker','Run the independent collector'),('sync','Run one scheduled collection pass')]:
        sub=commands.add_parser(command,help=description)
        sub.add_argument('--data-dir')
        if command=='sync':
            sub.add_argument('--sources',default='cisa,github,nvd,epss')
            sub.add_argument('--budget',type=int,default=300,help='Inventory processing budget in seconds.')
    sub=commands.add_parser('check',help='Check an actual manifest or SBOM; exit 0=pass, 1=violations, 2=incomplete.')
    sub.add_argument('manifest')
    sub.add_argument('--fail-on',choices=['kev','high','critical','priority'],default='kev')
    sub.add_argument('--threshold',type=int,default=70)
    sub.add_argument('--format',choices=['text','json','sarif'],default='text')
    sub.add_argument('--output')
    sub.add_argument('--data-dir',help='Optional reusable public catalog cache; otherwise use a temporary directory.')
    sub=commands.add_parser('export-site',help='Export a public static catalog from your collected records.')
    sub.add_argument('--data-dir')
    sub.add_argument('--output',required=True)
    sub.add_argument('--limit',type=int,default=10000)
    sub.add_argument('--base-url',default='')
    sub=commands.add_parser('user-reset',help='Recover an existing account using local filesystem access.')
    sub.add_argument('username')
    sub.add_argument('--data-dir')
    sub=commands.add_parser('backfill',help='Control optional historical NVD import.')
    sub.add_argument('action',choices=['start','pause','resume','restart','status'])
    sub.add_argument('--data-dir')
    args=parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING,format='%(levelname)s %(name)s: %(message)s')
    if args.command=='serve':
        from server import main as serve_main
        return serve_main(args.options)
    if args.command=='check':
        if not 0<=args.threshold<=100:
            parser.error('--threshold must be between 0 and 100.')
        return check(args)
    from services import Services
    services=Services(args.data_dir)
    try:
        if args.command=='worker':
            stopped=threading.Event()
            def shutdown(*_): stopped.set()
            signal.signal(signal.SIGINT,shutdown)
            signal.signal(signal.SIGTERM,shutdown)
            services.start_worker()
            print('MasterMonk collector running. Data: '+str(services.path),flush=True)
            while not stopped.wait(1):
                pass
        elif args.command=='sync':
            sources=set(args.sources.split(','))
            if not sources or sources-{'cisa','github','nvd','epss'} or not 0<=args.budget<=3600:
                parser.error('Choose supported source names and a budget of 0–3600 seconds.')
            services.once(sources,args.budget)
            health={s['id']:s for s in services.catalog.sources()}
            completed=services.catalog.state('sync',{}).get('successfulSources',[])
            print(json.dumps({'sources':{k:health[k] for k in sorted(sources)},'completed':completed},indent=2))
            return 0 if sources.issubset(completed) else 2
        elif args.command=='export-site':
            from static_export import export_site
            result=export_site(services.catalog,args.output,args.limit,args.base_url)
            print(json.dumps(result,indent=2))
        elif args.command=='user-reset':
            password=getpass.getpass('New password (15–128 characters): ')
            if password!=getpass.getpass('Repeat password: '):
                raise ValueError('The passwords do not match.')
            services.accounts.reset_password_local(args.username,password)
            print('Password changed; previous sessions and API tokens were revoked.')
        elif args.command=='backfill':
            print(json.dumps(services.backfill.status() if args.action=='status' else services.backfill.configure(args.action),indent=2))
        return 0
    finally:
        services.close()


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,RuntimeError) as exc:
        print('MasterMonk: '+str(exc),file=sys.stderr)
        raise SystemExit(2)
