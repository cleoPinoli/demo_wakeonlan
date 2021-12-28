# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hashlib
import logging
import random

from collections import (
    OrderedDict,
)

from cryptography.hazmat.backends import (
    default_backend,
)

from cryptography.hazmat.primitives import (
    hashes,
)

from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation,
    KBKDFHMAC,
    Mode,
)

from smbprotocol import (
    Dialects,
)

from smbprotocol.connection import (
    Capabilities,
    Ciphers,
    SecurityMode,
)

from smbprotocol.exceptions import (
    MoreProcessingRequired,
    SMBAuthenticationError,
    SMBException,
)

from smbprotocol.header import (
    Commands,
    NtStatus,
)

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    Structure,
)

log = logging.getLogger(__name__)


class SessionFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.6 SMB2 SESSION_SETUP Response Flags
    Flags the indicates additional information about the session.
    """
    SMB2_SESSION_FLAG_IS_GUEST = 0x0001
    SMB2_SESSION_FLAG_IS_NULL = 0x0002
    SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004


class SMB2SessionSetupRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.5 SMB2 SESSION_SETUP Request
    The SMB2 SESSION_SETUP Request packet is sent by the client to request a
    new authenticated session within a new or existing SMB 2 connection.
    """
    COMMAND = Commands.SMB2_SESSION_SETUP

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=25,
            )),
            ('flags', IntField(size=1)),
            ('security_mode', EnumField(
                size=1,
                enum_type=SecurityMode,
            )),
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities,
            )),
            ('channel', IntField(size=4)),
            ('security_buffer_offset', IntField(
                size=2,
                default=88,  # (header size 64) + (response size 24)
            )),
            ('security_buffer_length', IntField(
                size=2,
                default=lambda s: len(s['buffer']),
            )),
            ('previous_session_id', IntField(size=8)),
            ('buffer', BytesField(
                size=lambda s: s['security_buffer_length'].get_value(),
            )),
        ])
        super(SMB2SessionSetupRequest, self).__init__()


class SMB2SessionSetupResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.6 SMB2 SESSION_SETUP Response
    The SMB2 SESSION_SETUP Response packet is sent by the server in response to
    an SMB2 SESSION_SETUP Request.
    """
    COMMAND = Commands.SMB2_SESSION_SETUP

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9,
            )),
            ('session_flags', FlagField(
                size=2,
                flag_type=SessionFlags,
            )),
            ('security_buffer_offset', IntField(
                size=2,
                default=72,  # (header size 64) + (response size 8)
            )),
            ('security_buffer_length', IntField(
                size=2,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer', BytesField(
                size=lambda s: s['security_buffer_length'].get_value(),
            ))
        ])
        super(SMB2SessionSetupResponse, self).__init__()


class SMB2Logoff(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.7/8 SMB2 LOGOFF Request/Response
    Request and response to request the termination of a particular session as
    specified by the header.
    """
    COMMAND = Commands.SMB2_LOGOFF

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=4
            )),
            ('reserved', IntField(size=2))
        ])
        super(SMB2Logoff, self).__init__()


class Session(object):

    def __init__(self, connection, username=None, password=None,
                 require_encryption=True, auth_protocol='negotiate'):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.3 Per Session
        The Session object that is used to store the details for an
        authenticated SMB session. There are 4 forms of authentication that are
        supported;

        1. SSPI Auth, Windows only if pywin32 is installed. Uses either
            Kerberos or NTLM auth depending on the environment setup and can
            use the current user's credentials if none are provided here.
        2. NTLM Auth, requires the username and password
        3. Kerberos Auth, only available in certain circumstances
        4. Guest Auth, the credentials were rejected but the server allows a
            fallback to guest authentication (insecure and non-default)

        NTLM Auth is the fallback as it should be available in most scenarios
        while Kerberos only works on a system where python-gssapi is installed
        and the GGF extension for inquire_sec_context_by_oid is available
        (Linux), or pywin32 is installed (Windows).

        If using Kerberos Auth, the username and password can be omitted which
        means the default user kerb ticket (if available) is used. If the
        username is specified and not the password then it will get the kerb
        ticket for the principal specified (kinit must be used to get this
        ticket beforehand). If both the user and password are specified then
        it will get a ticket for the user instead of relying on the default
        store.

        If guest auth was negotiated based on a bad credential then signing
        and encryption is not allowed, for this to ultimately work the user
        must set require_signing=False when creating the Connection and
        require_encryption=False when creating the Session.

        :param connection: The Connection object that the session will use
        :param username: The username of the user to authenticate with
        :param password: The password of the user to authenticate with
        :param require_encryption: Whether any messages sent over the session
            require encryption regardless of the server settings (Dialects 3+),
            needs to be set to False for older dialects.
        :param auth_protocol: The protocol to use for authentication. Possible
            values are 'negotiate', 'ntlm' or 'kerberos'. Defaults to
            'negotiate'.
        """
        log.info("Initialising session with username: %s" % username)
        self._connected = False
        # This is only used by the client for pre-auth, the server will replace this value by one generated by itself.
        self.session_id = random.randint(1, 2147483647) * -1
        self.require_encryption = require_encryption

        # Table of tree connection, lookup by TreeConnect.tree_connect_id and
        # by share_name
        self.tree_connect_table = {}

        # First 16 bytes of the cryptographic key for this authenticated
        # context, right-padded with 0 bytes
        self.session_key = None

        self.signing_required = connection.require_signing
        self.connection = connection
        self.username = username
        self.password = password

        # No need to validate this as the spnego library will raise a ValueError
        self.auth_protocol = auth_protocol

        # Table of OpenFile, lookup by OpenFile.file_id
        self.open_table = {}

        # SMB 3.x+
        # List of Channel
        self.channel_list = []

        # 16-bit identifier incremented on a network disconnect that indicates
        # to the server the client's Channel change
        self.channel_sequence = None

        self.encrypt_data = None
        self.encryption_key = None
        self.decryption_key = None
        self.signing_key = None
        self.application_key = None
        self.full_session_key = None

        # SMB 3.1.1+
        # Preauth integrity value computed for the exhange of SMB2
        # SESSION_SETUP request and response for this session
        self.preauth_integrity_hash_value = []



    def disconnect(self, close=True):
        """
        Logs off the session

        :param close: Will close all tree connects in a session
        """
        if not self._connected:
            # already disconnected so let's return
            return

        if close:
            for open in list(self.open_table.values()):
                open.close(False)

            for tree in list(self.tree_connect_table.values()):
                tree.disconnect()

        log.info("Session: %s - Logging off of SMB Session" % self.username)
        logoff = SMB2Logoff()
        log.info("Session: %s - Sending Logoff message" % self.username)
        log.debug(logoff)
        request = self.connection.send(logoff, sid=self.session_id)

        log.info("Session: %s - Receiving Logoff response" % self.username)
        res = self.connection.receive(request)
        res_logoff = SMB2Logoff()
        res_logoff.unpack(res['data'].get_value())
        log.debug(res_logoff)
        self._connected = False
        del self.connection.session_table[self.session_id]

    def _smb3kdf(self, ki, label, context, length=16):
        """
        See SMB 3.x key derivation function
        https://blogs.msdn.microsoft.com/openspecification/2017/05/26/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys/

        :param ki: The session key is the KDK used as an input to the KDF
        :param label: The purpose of this derived key as bytes string
        :param context: The context information of this derived key as bytes
        :param length: The length of the key to generate
        string
        :return: Key derived by the KDF as specified by [SP800-108] 5.1
        """
        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=length,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=default_backend()
        )
        return kdf.derive(ki)
