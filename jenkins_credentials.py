#!/usr/bin/python

import os
import uuid
import base64
import random
from hashlib import sha256
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET

MAGIC = '::::MAGIC::::'
CREDENTIAL_FILE = 'credentials.xml'
MASTER_KEY_PATH = 'secrets/master.key'
HUDSON_UTIL_SECRET_PATH = 'secrets/hudson.util.Secret'


class BasicCredentials(object):
    module = None
    home_path = None
    data = {}
    root_type = 'com.cloudbees.plugins.credentials.SystemCredentialsProvider'
    parent_struct = {
        'domainCredentialsMap': {
            '@class': 'hudson.util.CopyOnWriteMap$Hash',
            'entry': {
                'com.cloudbees.plugins.credentials.domains.Domain': {
                    'specifications': {}
                },
                'java.util.concurrent.CopyOnWriteArrayList': {
                    '_return': None
                }
            }
        }
    }
    credential_type = 'basic'
    root_node = None
    parent_node = None
    credential_node = None

    def _set_data(self, key, value):
        self.data[key] = {
            '_text': value
        }

    def __init__(self, module, home_path, username, password, scope, description):
        self.module = module
        self.home_path = home_path
        self._set_data('username', username)
        self._set_data('password', self._encrypt(password))
        self._set_data('scope', scope.upper())
        self._set_data('description', description)
        self._read()

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())

    @staticmethod
    def _pad(s):
        bs = 16
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    def _create_secret_key(self):
        """
        Create a 256 byte random key, add le magic
        and pad it.
        :return:
        """
        return self._pad(os.urandom(256) + MAGIC)

    def _read_secret_key(self):
        secret_key_path = os.path.join(self.home_path, HUDSON_UTIL_SECRET_PATH)
        if os.path.exists(secret_key_path):
            return open(secret_key_path).read()
        else:
            data = self._create_secret_key()
            with open(secret_key_path, 'w') as f:
                f.write(data)
            return data

    def _encrypt(self, password):
        master_key = open(os.path.join(self.home_path, MASTER_KEY_PATH)).read()
        secret_key = self._read_secret_key()
        hashed_master_key = sha256(master_key).digest()[:16]
        k = AES.new(hashed_master_key, AES.MODE_ECB).decrypt(secret_key)[:-16]
        o = AES.new(k[:16], AES.MODE_ECB)
        return base64.encodestring(o.encrypt(self._pad(password + MAGIC))).strip()

    def _get_credentials_path(self):
        return os.path.join(self.home_path, CREDENTIAL_FILE)

    def _read(self):
        try:
            self.root_node = ET.parse(self._get_credentials_path()).getroot()
            return
        except IOError:
            pass
        except ET.ParseError:
            pass
        self.root_node = ET.Element(self.root_type)

    def _write(self):
        ET.ElementTree(self.root_node).write(self._get_credentials_path())

    def _get(self):
        changed, self.parent_node = self._save_dict(self.parent_struct, self.root_node)
        for node in self.parent_node.findall(self.credential_type):
            desc_node = node.find('description')
            if desc_node is not None and desc_node.text == self.data['description']['_text']:
                self.credential_node = node
                return True
        return False

    def _save(self):
        """ Save any differences from `self.data` onto `self.credential_node`
        """
        if self.credential_node is None:
            return False

        id_node = self.credential_node.find('id')
        changed, return_node = self._save_dict(self.data, self.credential_node)
        return changed, id_node

    def _save_dict(self, data, node, changed=False, return_node=None):
        for k, v in data.iteritems():
            if k[0] == '@':
                node.set(k[1:], v)
            elif k == '_text':
                if node.text != v:
                    node.text = v
                    changed = True
            elif k == '_return':
                return_node = node
            else:
                new_node = node.find(k)
                if new_node is None:
                    new_node = ET.SubElement(node, k)
                    changed = True
                changed, return_node = self._save_dict(v, new_node, changed, return_node)
        return changed, return_node

    def _create(self):
        # Create a new credential node
        self.credential_node = ET.SubElement(self.parent_node, self.credential_type)
        id_text = self._generate_id()
        self.data['id'] = {
            '_text': id_text
        }
        self._save()
        return id_text

    def present(self):
        if self._get():
            changed, id_node = self._save()
            if changed:
                self._write()
            return changed, id_node.text
        else:
            id_text = self._create()
            self._write()
            return True, id_text

    def absent(self):
        if self._get():
            self.parent_node.remove(self.credential_node)
            self._write()
            return True
        else:
            return False


class UsernamePasswordCredentials(BasicCredentials):
    credential_type = 'com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl'


class BasicSSHUserPrivateKeyCredentials(BasicCredentials):
    credential_type = 'com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey'

    def __init__(self, module, home_path, username, password, scope, description, private_key_file):
        super(BasicSSHUserPrivateKeyCredentials, self).__init__(module, home_path, username, password, scope,
                                                                description)
        self.data['privateKeySource'] = {
            '@class': 'com.cloudbees.jenkins.plugins.sshcredentials.impl'
                      '.BasicSSHUserPrivateKey$FileOnMasterPrivateKeySource',
            'privateKeyFile': {
                '_text': private_key_file
            }
        }
        self.data['passphrase'] = self.data.pop('password')


def main():
    argument_spec = dict(
        home=dict(required=False, default='/var/lib/jenkins/', type='str'),
        state=dict(required=False, choices=['present', 'absent'], default='present'),
        username=dict(required=True, type='str'),
        password=dict(required=False, type='str', default=''),
        private_key_file=dict(required=False, type='str'),
        desc=dict(required=True, type='str'),
        scope=dict(required=False, choices=['system', 'global'], default='system'),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    try:
        arguments = {
            'home_path': module.params.get('home'),
            'username': module.params.get('username'),
            'password': module.params.get('password'),
            'description': module.params.get('desc'),
            'scope': module.params.get('scope'),
        }

        if module.params.get('private_key_file') is None:
            credentials = UsernamePasswordCredentials(module=module, **arguments)
        else:
            arguments['private_key_file'] = module.params.get('private_key_file')
            credentials = BasicSSHUserPrivateKeyCredentials(module=module, **arguments)

        state = module.params.get('state')
        if state == 'present':
            changed, id_text = credentials.present()
            module.exit_json(changed=changed, id=id_text)
        elif state == 'absent':
            module.exit_json(changed=credentials.absent())

    except ValueError as e:
        module.fail_json(msg=str(e), rc=1)


from ansible.module_utils.basic import *
main()
