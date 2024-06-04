"""
Processing domains SPF records and write rbldnsd config files.
Include should look like this: v=spf1 include:%{ir}.<domain>.<zone> ~all"
"""

import asyncio
import dataclasses
import re
import os
import glob
import shutil
import signal
from datetime import datetime, timedelta
from time import strftime, localtime
from pathlib import Path
from os import environ
import json
import rollbar
from dotenv import load_dotenv
import dns.resolver
import requests
from jsonpath_ng.ext import parse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from nats.aio.client import Client as NATS

load_dotenv()
rollbar.init(
  access_token=environ.get('ROLLBAR_TOKEN'),
  environment=environ.get('ROLLBAR_ENV', 'local'),
  code_version=environ.get('EXPURGATE_VERSION', '1.0.0')
)

@dataclasses.dataclass
class SPFProcessor:
    """Processing SPF records for specific domain."""
    ip4_subnet_gen_reg = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([1-2][0-9]|[3][0-1])$'
    ip4_subnet_32_reg = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/32)?$'

    def __init__(self, source_prefix = '_wqjnwiwc'):
        self.source_prefix = source_prefix
        self.dns_cache = {}
        self.includes = []
        self.ipmonitor = []

    def handle_error(self, error):
        """Handling errors."""
        # TODO: a way to notify about errors
        print(str(error))

    def dns_lookup(self, domain, record_type):
        """Making dns lookup on specific domain and record type."""
        lookup_key = domain + "-" + record_type
        errors = []

        if lookup_key not in self.dns_cache:
            try:
                rrset = dns.resolver.resolve(domain, record_type).rrset
                lookup = [dns_record.to_text() for dns_record in rrset]
            except Exception as e:
                error = "DNS Resolution Error - " + record_type + ":" + domain + ' err: ' + str(e)
                errors.append(error)

                return None, errors

            self.dns_cache[lookup_key] = lookup

            return lookup, errors

        print("==[CACHE][" + domain + "] Grabbed from DNS Cache - " + record_type)

        return self.dns_cache[lookup_key], errors

    def process_spf(self, domain, depth = 0):
        """Processing SPF records for specific domain."""
        source_domain = self.source_prefix + "." + domain if depth == 0 else domain
        spf_records, errors = self.dns_lookup(source_domain, "TXT")
        process_result = {
            'domain': domain,
            'ip4': [],
            'ip6': [],
            'others': [],
            'spf_action': '~all',
        }

        if not spf_records:
            error = "==[ERROR][" + domain + "] No SPF Records Found"
            self.handle_error(error)
            errors.append(error)

            return process_result, errors

        for record in spf_records:
            if record is not None and re.match('^"v=spf1 ', record, re.IGNORECASE):
                spf_parts = record.replace("\" \"","").replace("\"","").split()

                for spf_part in spf_parts:
                    if re.match(r'^[+-~?](all)$', spf_part, re.IGNORECASE):
                        process_result["spf_action"] = spf_part

                    elif re.match('redirect=', spf_part, re.IGNORECASE):
                        _, redirect = spf_part.split('=')

                        if redirect != domain and redirect and redirect not in self.includes:
                            self.includes.append(redirect)
                            nested_result, nested_errors = self.process_spf(redirect, depth + 1)

                            if len(nested_errors) > 0:
                                errors.extend(nested_errors)
                            else:
                                process_result["ip4"].extend(nested_result["ip4"])
                                process_result["ip6"].extend(nested_result["ip6"])
                                process_result["others"].extend(nested_result["others"])

                    elif re.match(r'^(\+|)include:', spf_part, re.IGNORECASE) and "%{" not in spf_part:
                        _, include = spf_part.split(':')

                        if include != domain and include and include not in self.includes:
                            self.includes.append(include)
                            nested_result, nested_errors = self.process_spf(include, depth + 1)

                            if len(nested_errors) > 0:
                                errors.extend(nested_errors)
                            else:
                                process_result["ip4"].extend(nested_result["ip4"])
                                process_result["ip6"].extend(nested_result["ip6"])
                                process_result["others"].extend(nested_result["others"])
                        elif include:
                            warning = "WARNING: Loop or Duplicate: " + include + " in " + domain
                            print(warning)

                    elif re.match(r'^(\+|)ptr:', spf_part, re.IGNORECASE):
                        process_result["others"].append(spf_part)
                        self.ipmonitor.append(spf_part)

                    elif re.match(r'^(\+|)ptr', spf_part, re.IGNORECASE):
                        process_result["others"].append(spf_part + ':' + domain)
                        self.ipmonitor.append(spf_part + ':' + domain)

                    elif re.match(r'^(\+|)a:', spf_part, re.IGNORECASE):
                        _, a_domain = spf_part.split(':')
                        result = self.dns_lookup(a_domain, "A")
                        result6 = self.dns_lookup(a_domain, "AAAA")

                        if result:
                            result = [(x + ' # a:' + a_domain) for x in result]
                            result.sort()
                            process_result["ip4"].extend(result)

                        if result6:
                            result6 = [(x + ' # aaaa:' + a_domain) for x in result6]
                            result6.sort()
                            process_result["ip6"].extend(result6)

                    elif re.match(r'^(\+|)a', spf_part, re.IGNORECASE):
                        result = self.dns_lookup(domain, "A")
                        result6 = self.dns_lookup(domain, "AAAA")

                        if result:
                            result = [x + " # a(" + domain + ")" for x in result]
                            result.sort()
                            process_result["ip4"].extend(result)

                        if result6:
                            result6 = [x + " # aaaa(" + domain + ")" for x in result6]
                            result6.sort()
                            process_result["ip6"].extend(result6)

                    elif re.match(r'^(\+|)mx:', spf_part, re.IGNORECASE):
                        _, mx_domain = spf_part.split(':')
                        result = self.dns_lookup(mx_domain, "MX")

                        if result:
                            mx_records = []

                            for mx_record in result:
                                _, mx_server = mx_record.split(' ')
                                mx_records.append(mx_server)

                            mx_records.sort()

                            for hostname in mx_records:
                                result = self.dns_lookup(hostname, "A")
                                result6 = self.dns_lookup(hostname, "AAAA")

                                if result:
                                    result = [x + ' # ' + spf_part + '=>a:' + hostname for x in result]
                                    result.sort()
                                    process_result["ip4"].extend(result)

                                if result6:
                                    result6 = [x + ' # ' + spf_part + '=>aaaa:' + hostname for x in result6]
                                    result6.sort()
                                    process_result["ip6"].extend(result6)

                    elif re.match(r'^(\+|)mx', spf_part, re.IGNORECASE):
                        result = self.dns_lookup(domain, "MX")

                        if result:
                            mx_records = []

                            for mx_record in result:
                                _, mx_server = mx_record.split(' ')
                                mx_records.append(mx_server)

                            mx_records.sort()

                            for hostname in mx_records:
                                result = self.dns_lookup(hostname, "A")
                                result6 = self.dns_lookup(hostname, "AAAA")

                                if result:
                                    result = [x + ' # mx(' + domain + ')=>a:' + hostname for x in result ]
                                    result.sort()
                                    process_result["ip4"].extend(result)

                                if result6:
                                    result6 = [x + ' # mx(' + domain + ')=>aaaa:' + hostname for x in result6 ]
                                    result6.sort()
                                    process_result["ip6"].extend(result6)

                    elif re.match(r'^(\+|)ip4:', spf_part, re.IGNORECASE):
                        _, ip_v4 = re.split("ip4:", spf_part, flags=re.IGNORECASE)

                        if ip_v4 not in self.ipmonitor:
                            #later check IP against subnet and if present in subnet, ignore.
                            if re.match(self.ip4_subnet_gen_reg, ip_v4):
                                self.ipmonitor.append(ip_v4)
                                process_result["ip4"].append(ip_v4 + " # subnet:" + domain)
                            # later check IP against subnet and if present in subnet, ignore.
                            elif re.match(self.ip4_subnet_32_reg, ip_v4):
                                self.ipmonitor.append(ip_v4)
                                process_result["ip4"].append(ip_v4 + " # ip:" + domain)
                            else:
                                process_result["ip4"].append("# error:" + ip_v4 + " for " + domain)

                    elif re.match(r'(\+|)ip6:', spf_part, re.IGNORECASE):
                        _, ip_v6 = re.split("ip6:", spf_part, flags=re.IGNORECASE)

                        if ip_v6 not in self.ipmonitor:
                            self.ipmonitor.append(ip_v6)
                            process_result["ip6"].append(ip_v6 + " # " + domain)

                    elif re.match(r'v=spf1', spf_part, re.IGNORECASE):
                        pass

                    elif re.match(r'exists:', spf_part, re.IGNORECASE) or re.match(r'include:', spf_part, re.IGNORECASE):
                        print('Added to fail response record:', spf_part)
                        self.ipmonitor.append(spf_part)
                        process_result["others"].append(spf_part)

        return process_result, errors
    
    def get_rbldnsd_part(self, domain):
        """Process domain SPF and generate rbldnsd config file content."""
        spf_result, spf_errors = self.process_spf(domain)

        if len(spf_errors) == 0:
            ip_v4_part = []
            ip_v6_part = []
            ips_v4 = [x.strip(' ') for x in spf_result['ip4']]
            ips_v6 = [x.strip(' ') for x in spf_result['ip6']]
            ip_v4_part.append("$DATASET ip4set:" + domain + " " + domain)
            ip_v4_part.append(":3:v=spf1 ip4:$ " + spf_result['spf_action'])

            if len(spf_result['others']) > 0:
                spf_result['others'] = list(dict.fromkeys(spf_result['others'])) #dedupe
                ip_v4_block = [":99:v=spf1 " + ' '.join(spf_result['others']) + " " + spf_result['spf_action']]
                ip_v6_block = [":99:v=spf1 " + ' '.join(spf_result['others']) + " " + spf_result['spf_action']]
            else:
                ip_v4_block = [":99:v=spf1 " + spf_result['spf_action']]
                ip_v6_block = [":99:v=spf1 " + spf_result['spf_action']]

            ip_v4_block.append("0.0.0.0/1 # all other IPv4 addresses")
            ip_v4_block.append("128.0.0.0/1 # all other IP IPv4 addresses")
            ip_v6_part.append("$DATASET ip6trie:" + domain + " " + domain)
            ip_v6_part.append(":3:v=spf1 ip6:$ " + spf_result['spf_action'])
            ip_v6_block.append("0:0:0:0:0:0:0:0/0 # all other IPv6 addresses")
            header = [
                "# Automatically generated rbldnsd config for:" + domain + " @ " + str(datetime.now(tz=None)),
                "# IP & Subnet: " + str(len(ips_v4 + ips_v6)),
            ]
            rbldnsd_parts = header + ip_v4_part + list(set(ips_v4)) + ip_v4_block + ip_v6_part + list(set(ips_v6)) + ip_v6_block

            return rbldnsd_parts, spf_errors

        return "", spf_errors

    def reset(self):
        """Reset state."""
        self.dns_cache = {}
        self.includes = []
        self.ipmonitor = []


@dataclasses.dataclass
class RBLDNSDProcessor:
    """Processing rbldnsd config files."""
    ipmonitor_compare = {}

    def rbldns_refresh(self):
        """Notify rbldnsd to refresh the config file."""
        rbldnsdpid = Path('/var/run/rbldnsd.pid').read_text('utf-8').strip()
        print(f"Notifying rbldnsd there is a change and to refresh the config file(via SIGHUP to pid:{rbldnsdpid})")
        try:
            os.kill(int(rbldnsdpid), signal.SIGHUP)
        except Exception as e:
            print("Uh-oh! Something went wrong, check 'rbldnsd' is running :", e)
            rollbar.report_exc_info()
        else:
            print(f"Success notifying pid: {rbldnsdpid}")

    def combine_files(self, directory, extension, output_filename):
        """Combine files into one."""
        # Create full path for files to combine
        file_paths = glob.glob(os.path.join(directory, extension))
        # Define the output file path
        output_file_path = os.path.join(directory, output_filename)

        # Open the output file and write the contents of each input file
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for file_path in file_paths:
                with open(file_path, 'r', encoding='utf-8') as input_file:
                    output_file.write(input_file.read() + '\n')

    def write_to_disk(self, src_path, dst_path, rbldnsd_config):
        """Write config to a file."""
        with open(src_path, 'w', encoding='utf-8') as fp:
            fp.write('\n'.join(rbldnsd_config))
            
        if os.path.exists(dst_path) and os.path.exists('backups'):
            current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            backup_path = f"backups/{current_time}_{dst_path.split('/')[-1]}"
            shutil.copy(dst_path, backup_path)
            print('Backup created: ' + backup_path)

        shutil.move(src_path, dst_path)
        print('Writing config file:' + dst_path)

    def process_rbldnsd(self, domain):
        """Process rbldnsd config file for specific domain."""
        spf_processor = SPFProcessor(environ.get('SOURCE_PREFIX', None))
        print('started new processing for domain: ' + domain)
        config_parts, gen_errors = spf_processor.get_rbldnsd_part(domain)
        spf_processor.ipmonitor.sort()
        ipmonitor = spf_processor.ipmonitor
        changes_detected = 0
        ipmonitor_compare = self.ipmonitor_compare

        if len(gen_errors) > 0:
            err_msg = f"Error(s) occurred during processing domain: {domain}\n{'\n'.join(gen_errors)}"
            print(err_msg)
            rollbar.report_message(err_msg, level="error")
            print('Aborting further processing for domain.')
            return False

        print('Comparing CURRENT and PREVIOUS record for changes.')

        if (domain in ipmonitor_compare) and (ipmonitor_compare[domain] != ipmonitor):
            changes_detected += 1
            print('Change detected! domain:' + domain)
            # print('Previous Record: ' + str(ipmonitor_compare[domain]))
            # print('New Record: ' + str(ipmonitor))

            ips_added = [d for d in ipmonitor if d not in ipmonitor_compare[domain]]
            ips_removed = [d for d in ipmonitor_compare[domain] if d not in ipmonitor]

            # logs for changes
            # print('Change Summary: +' + str(ips_added) + ' -' + str(ips_removed) )

            change_result = (strftime("%Y-%m-%dT%H:%M:%S", localtime()) + ' | CHANGE:' + domain + " | " + "+" + str(ips_added) + " -" + str(ips_removed))

            print('Changes: ' + change_result)

            self.ipmonitor_compare[domain] = ipmonitor

        elif (domain in ipmonitor_compare) and (ipmonitor_compare[domain] == ipmonitor):
            print('Exact match! - No change detected')

        else:
            changes_detected += 1
            print('Change detected - First run, or a domain has only just been added.')

            self.ipmonitor_compare[domain] = ipmonitor

        if changes_detected > 0:
            src_path = r'output/' + domain.replace(".", "-") + ".staging"
            dst_path = r'output/' + domain.replace(".", "-") + ".rbldnsd"

            self.write_to_disk(src_path, dst_path, config_parts)

        return changes_detected > 0

    def reset(self):
        """Reset state."""
        self.ipmonitor_compare = {}

async def get_domains():
    """Get list of domains from AutoSPF"""
    domains = []
    try:
        nc = await get_nats_client()
        response = await nc.request('domains.list', b'list', timeout=15)
        domain_list = json.loads(response.data.decode())
        jsonpath_expression = parse("$..name")

        for match in jsonpath_expression.find(domain_list):
            domains.append(match.value)
    except Exception as e:
        print('error occured on getting domains from autospf: ', e)
        rollbar.report_exc_info()

    return domains

def rollbar_exception_catcher(func):
    """Catching errors and reporting to rollbar"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            rollbar.report_exc_info()
            raise e
    return wrapper

@rollbar_exception_catcher
async def process_domains():
    """Processing domains"""
    processor = RBLDNSDProcessor()
    domains = await get_domains()
    should_refresh = False
    
    for domain in domains:
        print('Processing domain: ' + domain)
        changed = processor.process_rbldnsd(domain)

        if changed:
            should_refresh = True

    if should_refresh:
        print('At least one domain changed, refreshing config')
        dst_path = r'/var/lib/rbldnsd/running-config'
        processor.combine_files('output', '*.rbldnsd', dst_path)
        processor.rbldns_refresh()
    else:
        print('No changes detected, skipping refresh')

@rollbar_exception_catcher
async def domain_process_event(msg):
    """Domain processing event from nats"""
    data = json.loads(msg.data.decode())
    domain = data['domain']
    print('Asked to process domain through nats: ' + domain)
    processor = RBLDNSDProcessor()
    changed = processor.process_rbldnsd(domain)

    if changed:
        print('Asked to parse domain, refreshing config')
        dst_path = r'/var/lib/rbldnsd/running-config'
        processor.combine_files('output', '*.rbldnsd', dst_path)
        processor.rbldns_refresh()

@rollbar_exception_catcher
async def domain_remove_event(msg):
    """Domain remove event from nats"""
    data = json.loads(msg.data.decode())
    domain = data['domain']
    print('Asked to remove domain through nats: ' + domain)
    domain_file = r'output/' + domain.replace(".", "-") + ".rbldnsd"
    
    if os.path.exists(domain_file):
        os.remove(domain_file)
        print('Removed domain file: ' + domain_file)
        processor = RBLDNSDProcessor()
        print('Removed domain, refreshing config')
        dst_path = r'/var/lib/rbldnsd/running-config'
        processor.combine_files('output', '*.rbldnsd', dst_path)
        processor.rbldns_refresh()

async def run_scheduler():
    """Running scheduler to process domains"""
    print('Running scheduler...')
    scheduler = AsyncIOScheduler()
    first_run_time = datetime.now() + timedelta(seconds=10)
    scheduler.add_job(
        process_domains,
        'interval',
        # seconds=10,
        minutes=2,
        max_instances=1,
        next_run_time=first_run_time
    )
    scheduler.start()
    print('Scheduler started...')

async def get_nats_client():
    """Build nats client."""
    print('Connecting to nats...')
    nc = NATS()
    server = environ.get('NATS_URL', 'nats://localhost:4222')
    user = environ.get('NATS_USER', None)
    password = environ.get('NATS_PASS', None)

    await nc.connect(server, user=user, password=password)

    return nc

async def run_nats():
    """Running nats listeners"""
    print('Running nats listeners...')
    nc = await get_nats_client()

    await nc.subscribe('domains.parse', cb=domain_process_event)
    await nc.subscribe('domains.remove', cb=domain_remove_event)
    print("Listening for messages through nats...")

async def main():
    """Main function to start all tasks."""
    await asyncio.gather(
        run_nats(),
        run_scheduler()
    )

if __name__ == '__main__':
    loop = asyncio.new_event_loop()

    try:
        loop.run_until_complete(main())
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        print("Received exit signal, shutting down...")
        tasks = asyncio.all_tasks(loop=loop)
        for task in tasks:
            task.cancel()
            try:
                loop.run_until_complete(task)  # Wait for task to be cancelled.
            except asyncio.CancelledError:
                pass
    finally:
        print("Shutting down...")
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        print("Shutdown complete.")
