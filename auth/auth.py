import hashlib
import jwt
import ldap


class LDAPAuth:
    def __init__(self, ldap_host, ldap_port, ldap_base_dn, ldap_admin, ldap_admin_password, secret_key):
        self.ldap_host = ldap_host
        self.ldap_port = ldap_port
        self.ldap_base_dn = ldap_base_dn
        self.ldap_admin = ldap_admin
        self.ldap_admin_password = ldap_admin_password
        self.ldap_connection = self.connect()

        self.secret_key = secret_key

    def connect(self):
        ldap_connection = ldap.initialize('ldap://' + self.ldap_host + ':' + str(self.ldap_port))
        ldap_connection.simple_bind_s(self.ldap_admin, self.ldap_admin_password)
        return ldap_connection

    def disconnect(self):
        self.ldap_connection.unbind()

    @staticmethod
    def hash_password(password) -> str:
        algorithm = hashlib.sha256()
        password_bytes = password.encode('utf-8')
        algorithm.update(password_bytes)
        password_hashed = algorithm.hexdigest()
        return password_hashed

    def generate_access_token(self, user_id: str) -> str:
        return jwt.encode({"user_id": user_id}, self.secret_key, algorithm="HS256")

    def validate_access_token(self, token: str) -> str | None:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms="HS256")
            return payload
        except:
            return None

    def add_user(self, username: str, password: str, user_id: str):
        try:
            self.ldap_connection.search_s(self.ldap_base_dn, ldap.SCOPE_SUBTREE, '(uid=' + user_id + ')')
            return (False, f'User ID: {user_id} already exists')
        except ldap.NO_SUCH_OBJECT:
            pass
        except ldap.SERVER_DOWN:
            return (False, 'LDAP server is down')

        dn = 'cn=' + username + ',' + self.ldap_base_dn
        attrs = [
            ('objectClass', [b'top', b'person', b'organizationalPerson', b'inetOrgPerson']),
            ('cn', username.encode('utf-8')),
            ('sn', username.encode('utf-8')),
            ('userPassword', self.hash_password(password).encode('utf-8')),
            ('uid', user_id.encode('utf-8'))
        ]
        try:
            self.ldap_connection.add_s(dn, attrs)
            return True
        except ldap.LDAPError as e:
            return False, e
        finally:
            self.disconnect()

    def authenticate(self, username, password):
        try:
            user_dn = 'cn=' + username + ',' + self.ldap_base_dn
            self.ldap_connection.simple_bind_s(user_dn, self.hash_password(password))
            return True
        except ldap.INVALID_CREDENTIALS:
            return (False, 'Invalid credentials')
        except ldap.SERVER_DOWN:
            return (False, 'LDAP server is down')
        except ldap.LDAPError as e:
            return False, e
        finally:
            self.disconnect()
