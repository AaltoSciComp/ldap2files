import os
import re
import logging
import sys
import pickle
import io
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
                 user_attrs=None,
                 group_attrs=None,
                 cert=None):

        self.server = server
        self.user_base = user_base
        self.group_base = group_base
        self.auth_type = auth_type
        self.cert = cert
        self.bind_user = bind_user
        self.bind_password = bind_password

        if not group_attrs:
            group_attrs = []
        group_attrs += ['cn', 'objectClass', 'member', 'gidNumber', 'sAMAccountName']
        self.group_attrs = list(set(group_attrs))

        if not user_attrs:
            user_attrs = []
        user_attrs += ['cn', 'objectClass', 'uidNumber', 'sAMAccountName', 'unixHomeDirectory', 'loginShell']
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

    def get_groups(self, groups, cache_file=None):
        if cache_file and os.path.isfile(cache_file):
            logging.debug('Using cached query from file: %s', cache_file)
            group_data = self.read_cache(cache_file)
            return group_data

        group_searches = defaultdict(list)
        for group in groups:
            cn, base = self.dn_split(group, self.group_base)
            #group_searches[base].append(f'(memberOf:1.2.840.113556.1.4.1941:={cn})')
            group_searches[base].append(f'({cn})')


        group_data = {}
        for group_base, group_list in group_searches.items():
            for group_search in self.split_list(group_list, 100):
                if len(group_search) > 1:
                    #ldap_filter = f'(&(objectCategory=group)(|{"".join(group_search)}))'
                    ldap_filter = f'(|{"".join(group_search)})'
                else:
                    #ldap_filter = f'(&(objectCategory=group){group_search[0]})'
                    ldap_filter = f'{group_search[0]}'

                logging.debug('Doing a query for groups from group base "%s" with ldap filter "%s".', group_base, ldap_filter)
                response = self.connection.search_s(group_base, ldap.SCOPE_SUBTREE, ldap_filter, self.group_attrs)
                self.num_queries += 1

                for dn, group_response in response:
                    group_data[dn] = group_response

        if cache_file:
            logging.debug('Caching query results to cache file "%s".', cache_file)
            self.write_cache(group_data, cache_file)

        return group_data

    def get_users(self, users, groups=False, cache_file=None):

        if cache_file and os.path.isfile(cache_file):
            logging.debug('Using cached query from file: %s', cache_file)
            user_data = self.read_cache(cache_file)
            return user_data

        attrs = self.user_attrs
        if groups:
            attrs = attrs + ['memberOf']

        user_searches = defaultdict(list)
        for user in users:
            cn, base = self.dn_split(user, self.user_base)
            user_searches[base].append(f'({cn})')

        user_data = {}
        for user_base, user_list in user_searches.items():
            for user_search_list in self.split_list(user_list, 100):
                if len(user_search_list) > 1:
                    #ldap_filter = f'(&(objectCategory=user)(|{"".join(user_search_list)}))'
                    ldap_filter = f'(|{"".join(user_search_list)})'
                else:
                    #ldap_filter = f'(&(objectCategory=user){user_search_list[0]})'
                    ldap_filter = f'{user_search_list[0]}'

                logging.debug('Doing a query for user base "%s" with ldap filter "%s".', user_base, ldap_filter)
                response = self.connection.search_s(user_base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
                self.num_queries += 1

                for dn, user_response in response:
                    user_data[dn] = user_response

        if cache_file:
            logging.debug('Caching query results to cache file "%s".', cache_file)
            self.write_cache(user_data, cache_file)

        return user_data


def get_config_opt(name, conf, arg, require=False):
    if arg is not None:
        return arg
    value = conf.get(name, None)
    if require:
        assert value is not None, f'{name} needs to be specified!'
    return value


def write_ldif(outputfile, user_datas, group_datas):


    with open(outputfile, 'w', encoding='utf-8') as f:
        ldif_writer = ldif.LDIFWriter(f)

        for dn, user_data in user_datas.items():
            ldif_writer.unparse(dn, user_data)

        for dn, group_data in group_datas.items():
            ldif_writer.unparse(dn, group_data)


def write_groups(user_data, groups_data):

    pass

@click.command()
@click.option('--config', default=None, type=click.Path(exists=True, readable=True), help='Configuration file to use')
@click.option('--groups', default=None, help='Groups to search from LDAP (comma separated list)')
@click.option('--server', default=None, help='AD server')
@click.option('--user-base', default=None, help='Group search base')
@click.option('--group-base', default=None, help='Group search base')
@click.option('--auth-type', default='gssapi', type=click.Choice(("bind", "gssapi")), help='Authentication type')
@click.option("--cert", default=None, type=click.Path(exists=True, readable=True), help='Path to certificates')
@click.option('--user', default=None, help='Username (only valid for bind auths)')
@click.option('--password', default=None, help='Password (only valid for bind auths)')
@click.option('--cache-primary/--no-cache-primary', default=False, help='Cache primary group members')
@click.option('--cache-primary-users/--no-cache-primary-users', default=False, help='Cache primary group users')
@click.option('--cache-secondary/--no-cache-secondary', default=False, help='Cache secondary group members')
@click.option('--cache-secondary-users/--no-cache-secondary-users', default=False, help='Cache secondary group users')
@click.option("--loglevel", default="info", type=click.Choice(("debug", "info", "warning")))
@click.option("--output-format", default="files", type=click.Choice(("files", "ldif")), help='Output file type')
@click.option("--output", default='data.ldif', help='Output file name (for ldif data)')
def ldap2files(config,
               groups,
               server,
               user_base,
               group_base,
               auth_type,
               cert,
               user,
               password,
               cache_primary,
               cache_primary_users,
               cache_secondary,
               cache_secondary_users,
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
    auth_type = get_config_opt('auth_type', c, auth_type, require=True)
    output_format = get_config_opt('output_format', c, output_format)
    cert = get_config_opt('cert', c, cert)
    user = get_config_opt('user', c, user)
    password = get_config_opt('password', c, password)

    if cache_primary:
        cache_primary = 'cache_primary.pickle'
    if cache_primary_users:
        cache_primary_users = 'cache_primary_users.pickle'
    if cache_secondary:
        cache_secondary = 'cache_secondary.pickle'
    if cache_secondary_users:
        cache_secondary_users = 'cache_secondary_users.pickle'

    with LDAPSearcher(server=server,
                      user_base=user_base,
                      group_base=group_base,
                      auth_type=auth_type,
                      cert=cert,
                      bind_user=user,
                      bind_password=password) as searcher:

        groups_searched = []
        users_searched = []

        logging.info('Searching for primary groups and their members')
        primary_groups_data = searcher.get_groups(primary_groups, cache_file=cache_primary)

        primary_members = []
        for dn, group_d in primary_groups_data.items():
            groups_searched.append(dn)
            primary_members.extend(group_d['member'])

        primary_members = set(primary_members)
        logging.info('Found %d group members in the primary group.', len(primary_members))

        logging.info("Searching for primary users and their group memberships")
        primary_users_data = searcher.get_users(primary_members, groups=True, cache_file=cache_primary_users)

        logging.info('Found %d primary users.', len(primary_users_data))

        secondary_groups = []
        for dn, user_d in primary_users_data.items():
            users_searched.append(dn)
            secondary_groups.extend([ group_cn for group_cn in user_d['memberOf'] if group_cn not in groups_searched ])

        secondary_groups = set(secondary_groups)
        logging.info('Found %d secondary groups.', len(secondary_groups))

        logging.info("Searching for secondary groups and their members")
        secondary_groups_data = searcher.get_groups(secondary_groups, cache_file=cache_secondary)
        secondary_members = []
        for dn, group_d in secondary_groups_data.items():
            groups_searched.append(dn)
            secondary_members.extend(group_d['member'])

        secondary_members = set(secondary_members) - primary_members

        logging.info('Found %d secondary users.', len(secondary_members))

        logging.info("Searching for secondary users")
        secondary_users_data = searcher.get_users(secondary_members, groups=False, cache_file=cache_secondary_users)
        logging.info('Found %d secondary users.', len(secondary_users_data))

        logging.info('Total number of queries made: %d.', searcher.num_queries)

        logging.debug('Checking for overlap between searches')
        logging.debug("Number of shared groups in searches: %d", len(set(primary_groups_data.keys()) & set(secondary_groups_data.keys())))
        logging.debug("Number of shared users in searches: %d", len(set(primary_users_data.keys()) & set(secondary_users_data.keys())))

        logging.debug('Combining group data')
        all_groups_data = {}
        all_groups_data.update(primary_groups_data)
        all_groups_data.update(secondary_groups_data)
        logging.debug('Combining user data')
        all_users_data = {}
        all_users_data.update(primary_users_data)
        all_users_data.update(secondary_users_data)
        if output_format == 'ldif':
            write_ldif(output, all_users_data, all_groups_data)

if __name__=="__main__":
    ldap2files()

