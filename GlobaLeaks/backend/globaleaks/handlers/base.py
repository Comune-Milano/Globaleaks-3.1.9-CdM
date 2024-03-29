# -*- coding: utf-8 -*-
#
# Base class for all the handlers
import base64
import collections
import copy
import json
import mimetypes
import os
import re
import shutil

from datetime import datetime
from cryptography.hazmat.primitives import constant_time
from six import text_type, binary_type
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks

from globaleaks.event import track_handler
from globaleaks.rest import errors, requests
from globaleaks.utils.securetempfile import SecureTemporaryFile
from globaleaks.utils.security import generateRandomKey, sha512
from globaleaks.settings import Settings
from globaleaks.utils.tempdict import TempDict
from globaleaks.utils.utility import datetime_now, deferred_sleep, log

HANDLER_EXEC_TIME_THRESHOLD = 120


class SessionsFactory(TempDict):
    """Extends TempDict to provide session management functions ontop of temp session keys"""
    def revoke_all_sessions(self, user_id):
        to_delete = []
        for other_session in Sessions.values():
            if other_session.user_id == user_id:
                log.debug("Revoking old session for %s", user_id)
                to_delete.append(other_session.id)

        for id in to_delete:
            Sessions.delete(id)

Sessions = SessionsFactory(timeout=Settings.authentication_lifetime)

# https://github.com/globaleaks/GlobaLeaks/issues/1601
mimetypes.add_type('image/svg+xml', '.svg')
mimetypes.add_type('application/vnd.ms-fontobject', '.eot')
mimetypes.add_type('application/x-font-ttf', '.ttf')
mimetypes.add_type('application/woff', '.woff')
mimetypes.add_type('application/woff2', '.woff2')


class FileProducer(object):
    """
    Streaming producer for files

    @ivar request: The L{IRequest} to write the contents of the file to.
    @ivar fileObject: The file the contents of which to write to the request.
    """
    bufferSize = Settings.file_chunk_size

    def __init__(self, request, filePath):
        self.finish = defer.Deferred()
        self.request = request
        self.fileSize = os.stat(filePath).st_size
        self.fileObject = open(filePath, "rb")
        self.bytesWritten = 0

    def start(self):
        self.request.registerProducer(self, False)
        return self.finish

    def resumeProducing(self):
        try:
            if self.request is not None:
                data = self.fileObject.read(self.bufferSize)
                if data:
                    self.bytesWritten += len(data)
                    self.request.write(data)

                if self.bytesWritten == self.fileSize:
                    self.stopProducing()
        except:
            pass

    def stopProducing(self):
        try:
            if self.request is not None:
                self.fileObject.close()
                self.request.unregisterProducer()
                self.request.finish()
                self.request = None
                self.finish.callback(None)
        except:
            pass


class Session(object):
    expireCall = None # attached to object by tempDict

    def __init__(self, tid, user_id, user_role, user_status, acp):
        self.id = generateRandomKey(42)
        self.tid = tid
        self.user_id = user_id
        self.user_role = user_role
        self.user_status = user_status
        self.acp = acp

    def getTime(self):
        return self.expireCall.getTime()


def new_session(tid, user_id, user_role, user_status, acp):
    session = Session(tid, user_id, user_role, user_status, acp)
    Sessions.revoke_all_sessions(user_id)
    Sessions.set(session.id, session)
    return session

def new_session_rec_auth(tid, user_id, user_role, user_status, acp):
    session = Session(tid, user_id, user_role, user_status, acp)
    #Sessions.revoke_all_sessions(user_id)
    #Sessions.set(session.id, session)
    return session

class BaseHandler(object):
    check_roles = 'admin'
    handler_exec_time_threshold = HANDLER_EXEC_TIME_THRESHOLD
    uniform_answer_time = False
    cache_resource = False
    invalidate_global_cache = False
    invalidate_cache = False
    invalidate_tenant_states = False
    bypass_basic_auth = False
    root_tenant_only = False
    upload_handler = False
    uploaded_file = None
    require_multisite = False

    def __init__(self, state, request):
        self.name = type(self).__name__
        self.state = state
        self.request = request
        self.request.start_time = datetime.now()

    @staticmethod
    def decorator_authentication(f, roles):
        """
        Decorator for authenticated sessions.
        """
        def wrapper(self, *args, **kwargs):
            if self.state.tenant_cache[self.request.tid].basic_auth and not self.bypass_basic_auth:
                self.basic_auth()

            if '*' in roles:
                return f(self, *args, **kwargs)

            if 'unauthenticated' in roles:
                if self.current_user:
                    raise errors.InvalidAuthentication

                return f(self, *args, **kwargs)

            if not self.current_user:
                raise errors.NotAuthenticated

            if self.current_user.user_role in roles:
                log.debug("Authentication OK (%s)", self.current_user.user_role)
                return f(self, *args, **kwargs)

            raise errors.InvalidAuthentication

        return wrapper

    @staticmethod
    def decorator_invalidate_tenant_states(f):
        """
        Decorator for invalidation of tenant states
        """
        def wrapper(self, *args, **kwargs):
            d = defer.maybeDeferred(f, self, *args, **kwargs)
            def callback(data):
                self.state.refresh_tenant_states()
                return data

            d.addCallback(callback)

            return d

        return wrapper

    def basic_auth(self):
        msg = None
        if b"authorization" in self.request.headers:
            try:
                auth_type, data = self.request.headers[b"authorization"].split()
                usr, pwd = base64.b64decode(data).split(":", 1)
                if auth_type != "Basic" or \
                    usr != self.state.tenant_cache[self.request.tid].basic_auth_username or \
                    pwd != self.state.tenant_cache[self.request.tid].basic_auth_password:
                    msg = "Authentication failed"
            except AssertionError:
                msg = "Authentication failed"
        else:
            msg = "Authentication required"

        if msg is not None:
            self.request.setHeader("WWW-Authenticate", "Basic realm=\"globaleaks\"")
            raise errors.HTTPAuthenticationRequired()

    @staticmethod
    def validate_python_type(value, python_type):
        """
        Return True if the python class instantiates the specified python_type.
        """
        if value is None:
            return True

        if python_type == requests.SkipSpecificValidation:
            return True

        if python_type == int:
            try:
                int(value)
                return True
            except:
                return False

        if python_type == bool:
            if value == u'true' or value == u'false':
                return True

        return isinstance(value, python_type)

    @staticmethod
    def validate_regexp(value, type):
        """
        Return True if the python class matches the given regexp.
        """
        try:
            value = text_type(value)
        except:
            return False

        return bool(re.match(type, value))

    @staticmethod
    def validate_type(value, type):
        retval = False

        if value is None:
            log.err("-- Invalid python_type, in [%s] expected %s", value, type)

        # if it's callable, than assumes is a primitive class
        elif callable(type):
            retval = BaseHandler.validate_python_type(value, type)
            if not retval:
                log.err("-- Invalid python_type, in [%s] expected %s", value, type)

        # value as "{foo:bar}"
        elif isinstance(type, collections.Mapping):
            retval = BaseHandler.validate_jmessage(value, type)
            if not retval:
                log.err("-- Invalid JSON/dict [%s] expected %s", value, type)

        # regexp
        elif isinstance(type, str):
            retval = BaseHandler.validate_regexp(value, type)
            if not retval:
                log.err("-- Failed Match in regexp [%s] against %s", value, type)

        # value as "[ type ]"
        elif isinstance(type, collections.Iterable):
            # empty list is ok
            if not value:
                retval = True

            else:
                retval = all(BaseHandler.validate_type(x, type[0]) for x in value)
                if not retval:
                    log.err("-- List validation failed [%s] of %s", value, type)

        return retval

    @staticmethod
    def validate_jmessage(jmessage, message_template):
        """
        Takes a string that represents a JSON messages and checks to see if it
        conforms to the message type it is supposed to be.

        This message must be either a dict or a list. This function may be called
        recursively to validate sub-parameters that are also go GLType.

        message: the message string that should be validated

        message_type: the GLType class it should match.
        """
        if isinstance(message_template, dict):
            success_check = 0
            keys_to_strip = []
            for key, value in jmessage.items():
                if key not in message_template:
                    # strip whatever is not validated
                    #
                    # reminder: it's not possible to raise an exception for the
                    # in case more values are present because it's normal that the
                    # client will send automatically more data.
                    #
                    # e.g. the client will always send 'creation_date' attributes of
                    #      objects and attributes like this are present generally only
                    #      from the second request on.
                    #
                    keys_to_strip.append(key)
                    continue

                if not BaseHandler.validate_type(value, message_template[key]):
                    log.err("Received key %s: type validation fail", key)
                    raise errors.InputValidationError("Key (%s) type validation failure" % key)
                success_check += 1

            for key in keys_to_strip:
                del jmessage[key]

            for key, value in message_template.items():
                if key not in jmessage:
                    log.debug("Key %s expected but missing!",  key)
                    log.debug("Received schema %s - Expected %s",
                              jmessage.keys(), message_template.keys())
                    raise errors.InputValidationError("Missing key %s" % key)

                if not BaseHandler.validate_type(jmessage[key], value):
                    log.err("Expected key: %s type validation failure", key)
                    raise errors.InputValidationError("Key (%s) double validation failure" % key)

                if isinstance(message_template[key], dict) or isinstance(message_template[key], list):
                    if message_template[key]:
                        BaseHandler.validate_jmessage(jmessage[key], message_template[key])

                success_check += 1

            if success_check != len(message_template) * 2:
                log.err("Success counter double check failure: %d", success_check)
                raise errors.InputValidationError("Success counter double check failure")

            return True

        elif isinstance(message_template, list):
            if not all(BaseHandler.validate_type(x, message_template[0]) for x in jmessage):
                raise errors.InputValidationError("Not every element in %s is %s" %
                                                (jmessage, message_template[0]))
            return True

        else:
            raise errors.InputValidationError("invalid json massage: expected dict or list")

    @staticmethod
    def validate_message(message, message_template):
        try:
            if isinstance(message, binary_type):
                message = message.decode('utf-8')

            jmessage = json.loads(message)
        except ValueError:
            raise errors.InputValidationError("Invalid JSON format")

        if BaseHandler.validate_jmessage(jmessage, message_template):
            return jmessage

        raise errors.InputValidationError("Unexpected condition!?")

    def redirect(self, url):
        self.request.setResponseCode(301)
        self.request.setHeader(b"location", url)
        self.request.finish()

    def write_file(self, filename, filepath):
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise errors.ResourceNotFound()

        if filename.endswith('.gz'):
            self.request.setHeader("Content-encoding", "gzip")
            filename = filename[:-3]

        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            self.request.setHeader("Content-Type", mime_type)

        return FileProducer(self.request, filepath).start()

    def force_file_download(self, filename, filepath):
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise errors.ResourceNotFound()

        self.request.setHeader('X-Download-Options', 'noopen')
        self.request.setHeader('Content-Type', 'application/octet-stream')
        self.request.setHeader('Content-Disposition', 'attachment; filename=\"%s\"' % filename)

        return FileProducer(self.request, filepath).start()

    def get_current_user(self):
        api_session = self.get_api_session()
        if api_session is not None:
            return api_session

        # Check for the session header
        session_id = self.request.headers.get(b'x-session')
        if session_id is None:
            return None

        # Check that that provided session exists and is legit

        # We need to convert here to text_type as sessions generate a
        # random string in text form. It seems sessions assume that it will
        # be a string while twisted returns headers in bytes

        session = Sessions.get(text_type(session_id, 'utf-8'))
        if session is None or session.tid != self.request.tid:
            return None

        return session

    @property
    def current_user(self):
        if not hasattr(self, '_current_user'):
            self._current_user = self.get_current_user()

        return self._current_user

    def get_api_session(self):
        token = ''
        if b'api-token' in self.request.args:
            token = binary_type(self.request.args[b'api-token'][0])
        elif b'x-api-token' in self.request.headers:
            token = binary_type(self.request.headers[b'x-api-token'])

        # Assert the input is okay and the api_token state is acceptable
        if self.request.tid != 1 or \
           len(token) != Settings.api_token_len or \
           self.state.api_token_session is None or \
           not self.state.tenant_cache[self.request.tid].admin_api_token_digest:
            return None

        stored_token_hash = self.state.tenant_cache[self.request.tid].admin_api_token_digest.encode()

        if constant_time.bytes_eq(sha512(token), stored_token_hash):
            return self.state.api_token_session
        return None

    def process_file_upload(self):
        if b'flowFilename' not in self.request.args:
            return None

        total_file_size = int(self.request.args[b'flowTotalSize'][0])
        flow_identifier = self.request.args[b'flowIdentifier'][0]

        chunk_size = len(self.request.args[b'file'][0])
        if ((chunk_size / (1024 * 1024)) > self.state.tenant_cache[self.request.tid].maximum_filesize or
            (total_file_size / (1024 * 1024)) > self.state.tenant_cache[self.request.tid].maximum_filesize):
            log.err("File upload request rejected: file too big", tid=self.request.tid)
            raise errors.FileTooBig(self.state.tenant_cache[self.request.tid].maximum_filesize)

        if flow_identifier not in self.state.TempUploadFiles:
            self.state.TempUploadFiles.set(flow_identifier, SecureTemporaryFile(Settings.tmp_path))

        f = self.state.TempUploadFiles[flow_identifier]
        with f.open('w') as f:
            f.write(self.request.args[b'file'][0])

            if self.request.args[b'flowChunkNumber'][0] != self.request.args[b'flowTotalChunks'][0]:
                return None
            else:
                f.finalize_write()

        mime_type, _ = mimetypes.guess_type(text_type(self.request.args[b'flowFilename'][0], 'utf-8'))
        if mime_type is None:
            mime_type = 'application/octet-stream'

        self.uploaded_file = {
            'date': datetime_now(),
            'name': self.request.args[b'flowFilename'][0],
            'type': mime_type,
            'size': total_file_size,
            'filename': os.path.basename(f.filepath),
            'body': f,
            'description': self.request.args.get(b'description', [''])[0]
        }

    def write_upload_plaintext_to_disk(self, destination):
        """
        @param uploaded_file: uploaded_file data struct
        @param the file destination
        @return: a descriptor dictionary for the saved file
        """
        try:
            log.debug('Creating file %s with %d bytes', destination, self.uploaded_file['size'])

            with self.uploaded_file['body'].open('r') as encrypted_file, open(destination, 'wb') as plaintext_file:
                while True:
                    chunk = encrypted_file.read(4096)
                    if not chunk:
                        break

                    plaintext_file.write(chunk)

        finally:
            self.uploaded_file['path'] = destination

    @inlineCallbacks
    def execution_check(self):
        self.request.execution_time = datetime.now() - self.request.start_time

        if self.request.execution_time.seconds > self.handler_exec_time_threshold:
            err_tup = ("Handler [%s] exceeded execution threshold (of %d secs) with an execution time of %.2f seconds",
                       self.name, self.handler_exec_time_threshold, self.request.execution_time.seconds)
            log.err(tid=self.request.tid, *err_tup)
            self.state.schedule_exception_email(*err_tup)

        track_handler(self)

        if self.uniform_answer_time:
            needed_delay = (Settings.side_channels_guard - (self.request.execution_time.microseconds / 1000)) / 1000
            if needed_delay > 0:
                yield deferred_sleep(needed_delay)
