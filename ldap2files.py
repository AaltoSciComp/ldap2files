import os
import re
import logging
import sys
import pickle
import sys
from collections import defaultdict

import click
import ldap
import ldif

import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class LDAPSearcher:

    def __init__(self,
                 server=None,
                 user_base=None,
                 group_base=None,
                 auth_type=None,
                 bind_user=None,
                 bind_password=None,
                 extra_user_attrs=None,
                 extra_group_attrs=None,
                 cert=None):

        self.server = server
        self.user_base = user_base
        self.group_base = group_base
        self.auth_type = auth_type
        self.cert = cert
        self.bind_user = bind_user
        self.bind_password = bind_password

        group_attrs = ['cn', 'objectClass', 'member', 'gidNumber', 'sAMAccountName']
        group_attrs.extend(extra_group_attrs)
        self.group_attrs = list(set(group_attrs))

        user_attrs = ['cn', 'objectClass', 'uidNumber', 'sAMAccountName']
        user_attrs.extend(extra_user_attrs)
        self.user_attrs = list(set(user_attrs))

        self.connection = None

        self.num_queries = 0

    def __enter__(self):
        assert self.server is not None, 'Server not set!'
        uri = f'ldap://{self.server}'

        logging.debug('Connecting to server via URI: %s', uri)
        ldap_con = ldap.initialize(uri)

        if self.auth_type == 'gssapi':
            logging.debug('Connecting using GSSAPI authentication.')
            ldap_con.sasl_non_interactive_bind_s('GSSAPI')
        elif self.auth_type == 'bind':
            logging.debug('Connecting using bind authentication.')
            logging.debug('Using certificate "%s" for TLS encryption.', self.cert)
            assert self.bind_user is not None, 'User for bind login is not set!'
            assert self.bind_password is not None, 'Password for bind login is not set!'
            ldap_con.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            ldap_con.set_option(ldap.OPT_X_TLS_CACERTFILE, self.cert)
            ldap_con.set_option(ldap.OPT_X_TLS_NEWCTX,0)
            ldap_con.start_tls_s()

            logging.debug('Connecting as user: %s', self.bind_user)
            ldap_con.simple_bind_s(self.bind_user, self.bind_password)
        logging.debug('Connection created as: %s', ldap_con.whoami_s())

        self.connection = ldap_con
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        self.connection.unbind_s()

        return False

    @staticmethod
    def read_cache(cache_file):
        with open(cache_file, 'rb') as f:
            d = pickle.load(f)
        return d

    @staticmethod
    def write_cache(obj, cache_file):
        with open(cache_file, 'wb') as f:
            d = pickle.dump(obj, f)

    @staticmethod
    def dn_split(obj, default_base):
        if isinstance(obj, bytes):
            obj_name = obj.decode('utf-8')
        else:
            obj_name = obj
        match = re.match('^CN=([^,]+),.*$', obj_name)
        if match:
            dn, base = obj_name.split(',', 1)
        else:
            dn = f'CN={obj_name}'
            base = default_base
        return dn, base

    @staticmethod
    def split_list(l, n=100):
        for i in range(0, len(l), n):
            yield l[i:i+n]

    def run_search(self, search_dict, attrs, common_filter=None, cache_file=None):

        if cache_file and os.path.isfile(cache_file):
            logging.debug('Using cached query from file: %s', cache_file)
            data = self.read_cache(cache_file)
            return data

        data = {}
        for base, ldap_filters in search_dict.items():
            for grouped_search in self.split_list(ldap_filters, 100):
                if len(grouped_search) > 1:
                    ldap_filter = f'(|{"".join(grouped_search)})'
                else:
                    ldap_filter = f'{grouped_search[0]}'

                if common_filter:
                    ldap_filter = f'(&{common_filter}{ldap_filter})'

                logging.debug('Doing a query with base "%s" and ldap filter "%s".', base, ldap_filter)
                response = self.connection.search_s(base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
                self.num_queries += 1

                for dn, dn_data in response:
                    if not isinstance(dn, bytes):
                        dn = bytes(dn, 'utf-8')
                    data[dn] = dn_data

        if cache_file:
            logging.debug('Caching query results to cache file "%s".', cache_file)
            self.write_cache(data, cache_file)

        return data


    def get_groups(self, groups, cache_file=None):

        common_filter = '(objectCategory=group)'
        group_searches = defaultdict(list)
        for group in groups:
            cn, base = self.dn_split(group, self.group_base)
            group_searches[base].append(f'({cn})')

        logging.debug('Doing a query for the following groups: %s', groups)
        group_data = self.run_search(group_searches,
                                     self.group_attrs,
                                     common_filter=common_filter,
                                     cache_file=cache_file)

        return group_data

    def get_users(self, users, groups=False, cache_file=None):

        attrs = self.user_attrs
        if groups:
            attrs = attrs + ['memberOf']

        common_filter ='(objectCategory=user)'
        user_searches = defaultdict(list)
        for user in users:
            cn, base = self.dn_split(user, self.user_base)
            user_searches[base].append(f'({cn})')

        logging.debug('Doing a query for the following users: %s.', users)
        user_data = self.run_search(user_searches,
                                    attrs,
                                    common_filter=common_filter,
                                    cache_file=cache_file)

        return user_data


    def get_groups_users(self, group_dns, cache_file=None):

        attrs = ['dn']

        common_filter ='(objectCategory=user)'
        member_searches = defaultdict(list)
        for dn in group_dns:
            if isinstance(dn, bytes):
                dn = dn.decode('utf-8')
            member_searches[self.user_base].append(f'(memberOf:1.2.840.113556.1.4.1941:={dn})')

        logging.debug('Doing a query for users in these groups: %s', group_dns)
        user_data = self.run_search(member_searches,
                                    attrs,
                                    common_filter=common_filter,
                                    cache_file=cache_file)

        return user_data


def get_config_opt(name, conf, arg, require=False):
    if arg is not None:
        return arg
    value = conf.get(name, None)
    if require:
        assert value is not None, f'{name} needs to be specified!'
    return value


def override_values(datadict, overrides):
    for attr, override_fmt in overrides.items():
        logging.debug('Running override for %s with format: %s', attr, override_fmt)
        for dn in datadict.keys():
            data_decoded = {}
            for key,value in datadict[dn].items():
                if len(value) == 1:
                    data_decoded[key] = value[0].decode('utf-8')
            datadict[dn][attr] = [bytes(override_fmt.format(**data_decoded), encoding='utf-8')]
    return datadict


def write_ldif(outputfile, user_datas, group_datas):

    with open(outputfile, 'w', encoding='utf-8') as f:
        ldif_writer = ldif.LDIFWriter(f)

        for dn, user_data in user_datas.items():
            dn = dn.decode('utf-8')
            ldif_writer.unparse(dn, user_data)

        for dn, group_data in group_datas.items():
            dn = dn.decode('utf-8')
            ldif_writer.unparse(dn, group_data)


def write_files(user_datas, group_datas, primary_user_gid=None):

    uids = { dn:user_datas[dn]['uidNumber'] for dn in user_datas }
    nuids = len(uids)

    uids = { dn:uid for dn,uid in uids.items() if uid is not None }
    nuids_pruned = len(uids)

    if nuids != nuids_pruned:
        logging.debug('Encountered %d users without UIDs. Skipping them.', nuids-nuids_pruned)

    gids = { dn:group_datas[dn].get('gidNumber',None) for dn in group_datas }
    ngids = len(gids)

    gids = { dn:gid for dn,gid in gids.items() if gid is not None }
    ngids_pruned = len(gids)

    if ngids != ngids_pruned:
        logging.debug('Encountered %d groups without GIDs. Skipping them.', ngids-ngids_pruned)

    with open('passwd', 'w', encoding='utf-8') as f:

        for dn, user_data in user_datas.items():
            samaccountname = user_data['sAMAccountName']
            print(samaccountname, primary_user_gid)


@click.command()
@click.option('--config', default=None, type=click.Path(exists=True, readable=True), help='Configuration file to use')
@click.option('--groups', default=None, help='Groups to search from LDAP (comma separated list)')
@click.option('--server', default=None, help='AD server')
@click.option('--user-base', default=None, help='Group search base')
@click.option('--group-base', default=None, help='Group search base')
@click.option('--extra-user-attrs', default=None, help='Extra user attributes')
@click.option('--extra-group-attrs', default=None, help='Extra group attributes to search')
@click.option('--auth-type', default='gssapi', type=click.Choice(("bind", "gssapi")), help='Authentication type')
@click.option("--cert", default=None, type=click.Path(exists=True, readable=True), help='Path to certificates')
@click.option('--user', default=None, help='Username (only valid for bind auths)')
@click.option('--password', default=None, help='Password (only valid for bind auths)')
@click.option('--primary-user-gid', default=None, help='Primary GID for users (only valid for files)')
@click.option('--recursive-primary/--no-recursive-primary', default=None, help='Whether primary group search should be recurive or not')
@click.option('--secondary-users/--primary-users-only', default=False, help='Whether primary group search should be recurive or not')
@click.option('--cache-primary/--no-cache-primary', default=False, help='Cache primary group members')
@click.option('--cache-primary-users-names/--no-cache-primary-users-names', default=False, help="Cache primary group users' names")
@click.option('--cache-primary-users/--no-cache-primary-users', default=False, help='Cache primary group users')
@click.option('--cache-secondary/--no-cache-secondary', default=False, help='Cache secondary group members')
@click.option('--cache-secondary-users/--no-cache-secondary-users', default=False, help='Cache secondary group users')
@click.option('--cache-all/--no-cache-all', default=False, help='Cache all steps')
@click.option("--loglevel", default="info", type=click.Choice(("debug", "info", "warning")))
@click.option("--output-format", default="files", type=click.Choice(("files", "ldif")), help='Output file type')
@click.option("--output", default='data.ldif', help='Output file name (for ldif data)')
def ldap2files(config,
               groups,
               server,
               user_base,
               group_base,
               extra_user_attrs,
               extra_group_attrs,
               auth_type,
               cert,
               user,
               password,
               primary_user_gid,
               recursive_primary,
               secondary_users,
               cache_primary,
               cache_primary_users_names,
               cache_primary_users,
               cache_secondary,
               cache_secondary_users,
               cache_all,
               loglevel,
               output_format,
               output):

    loglevel = loglevel.upper()
    logging.getLogger().setLevel(loglevel)

    c = {}
    if config:
        with open(config, 'r') as f:
            c.update(yaml.load(f, Loader=Loader))

    primary_groups = get_config_opt('groups', c, groups, require=True).split(',')
    server = get_config_opt('server', c, server, require=True)
    user_base = get_config_opt('user_base', c, user_base, require=True)
    group_base = get_config_opt('group_base', c, group_base, require=True)
    extra_user_attrs = get_config_opt('extra_user_attrs', c, extra_user_attrs).split(',')
    extra_group_attrs = get_config_opt('extra_group_attrs', c, extra_group_attrs).split(',')
    auth_type = get_config_opt('auth_type', c, auth_type, require=True)
    output_format = get_config_opt('output_format', c, output_format)
    primary_user_gid = get_config_opt('primary_user_gid', c, primary_user_gid)
    recursive_primary = get_config_opt('recursive_primary', c, recursive_primary)
    get_secondary_users = get_config_opt('secondary_users', c, secondary_users)

    user_overrides = get_config_opt('user_overrides', c, None)
    if not user_overrides:
        user_overrides = {}
    group_overrides = get_config_opt('group_overrides', c, None)
    if not group_overrides:
        group_overrides = {}

    cert = get_config_opt('cert', c, cert)
    user = get_config_opt('user', c, user)
    password = get_config_opt('password', c, password)

    if cache_primary or cache_all:
        cache_primary = 'cache_primary.pickle'
    if cache_primary_users_names or cache_all:
        cache_primary_users_names = 'cache_primary_users_names.pickle'
    if cache_primary_users or cache_all:
        cache_primary_users = 'cache_primary_users.pickle'
    if cache_secondary or cache_all:
        cache_secondary = 'cache_secondary.pickle'
    if cache_secondary_users or cache_all:
        cache_secondary_users = 'cache_secondary_users.pickle'

    with LDAPSearcher(server=server,
                      user_base=user_base,
                      group_base=group_base,
                      auth_type=auth_type,
                      extra_user_attrs=extra_user_attrs,
                      extra_group_attrs=extra_group_attrs,
                      cert=cert,
                      bind_user=user,
                      bind_password=password) as searcher:

        groups_searched = []
        users_searched = []

        logging.info('Searching for primary groups and their members')
        primary_groups_data = searcher.get_groups(primary_groups, cache_file=cache_primary)
        primary_groups = []
        primary_users_names = []
        for dn, group_d in primary_groups_data.items():
            primary_groups.append(dn)
            groups_searched.append(dn)
            primary_users_names.extend(group_d['member'])
        primary_groups = set(primary_groups)
        logging.info('Found %d primary groups.', len(primary_groups))

        logging.info("Searching for primary users")
        if recursive_primary:
            # Do recursive search for users in group dn if needed
            primary_users_names = searcher.get_groups_users(primary_groups, cache_file=cache_primary_users_names).keys()
        logging.info('Found %d primary users.', len(primary_users_names))
        logging.info("Searching for primary users' group memberships")
        primary_users_data = searcher.get_users(primary_users_names, groups=True, cache_file=cache_primary_users)

        primary_users = []
        secondary_groups = []
        for dn, user_d in primary_users_data.items():
            primary_users.append(dn)
            users_searched.append(dn)
            secondary_groups.extend(user_d['memberOf'])

        primary_users = set(primary_users)
        logging.info('Found group data for %d primary users.', len(primary_users_data))
        secondary_groups = set(secondary_groups) - primary_groups
        logging.info('Found %d secondary groups.', len(secondary_groups))

        logging.info("Searching for secondary groups and their members")
        secondary_groups_data = searcher.get_groups(secondary_groups, cache_file=cache_secondary)
        secondary_users = []
        for dn, group_d in secondary_groups_data.items():
            groups_searched.append(dn)
            secondary_users.extend(group_d['member'])
        secondary_users = set(secondary_users) - primary_users

        if get_secondary_users:
            logging.info('Found %d secondary users.', len(secondary_users))
            logging.info("Searching for secondary users")
            secondary_users_data = searcher.get_users(secondary_users, groups=False, cache_file=cache_secondary_users)
            logging.info('Found %d secondary users.', len(secondary_users_data))
        else:
            logging.info('Skipping search of secondary users.')
            secondary_users_data = {}
            logging.info("Pruning secondary users from secondary groups' members")
            for dn, group_d in secondary_groups_data.items():
                members=group_d['member']
                members_pruned = [ member for member in members if member in primary_users_data ]
                users_pruned = len(members) - len(members_pruned)
                if users_pruned > 0:
                    logging.debug('Pruning %d members from group %s.', users_pruned, dn)
                group_d['member'] = members_pruned

        logging.info('Total number of queries made: %d.', searcher.num_queries)

        logging.debug('Checking for overlap between searches')
        logging.debug("Number of shared groups in searches: %d", len(set(primary_groups_data.keys()) & set(secondary_groups_data.keys())))
        logging.debug("Shared groups: %s", set(primary_groups_data.keys()) & set(secondary_groups_data.keys()))
        logging.debug("Number of shared users in searches: %d", len(set(primary_users_data.keys()) & set(secondary_users_data.keys())))
        logging.debug("Shared users: %s", set(primary_users_data.keys()) & set(secondary_users_data.keys()))

        logging.debug('Combining group data')
        all_groups_data = {}
        all_groups_data.update(primary_groups_data)
        all_groups_data.update(secondary_groups_data)
        logging.debug('Combining user data')
        all_users_data = {}
        all_users_data.update(primary_users_data)
        all_users_data.update(secondary_users_data)

        if len(group_overrides) > 0:
            logging.info('Running override for groups')
            all_groups_data = override_values(all_groups_data, group_overrides)
        if len(user_overrides) > 0:
            logging.info('Running override for users')
            all_users_data = override_values(all_users_data, user_overrides)

        if output_format == 'ldif':
            write_ldif(output, all_users_data, all_groups_data)
        if output_format == 'files':
            write_files(all_users_data, all_groups_data, primary_user_gid=primary_user_gid)

if __name__=="__main__":
    ldap2files()
