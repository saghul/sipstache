
import hashlib
import os
import re
import shutil

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from application.system import makedirs
from eventlib import api
from twisted.internet import reactor
from sipsimple.account import AccountManager
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import Engine, SIPURI
from sipsimple.core import Header, ContactHeader, FromHeader, ToHeader
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.streams import FileTransferStream
from sipsimple.streams.msrp import FileSelector
from sipsimple.threading import run_in_thread, run_in_twisted_thread
from sipsimple.threading.green import run_in_green_thread
from zope.interface import implements

from sylk.applications import SylkApplication, ApplicationLogger
from sylk.configuration import SIPConfig, ThorNodeConfig
from sylk.session import Session

from moustachefy import moustachefy


log = ApplicationLogger.for_package(__package__)


def format_identity(identity):
    return u'%s <sip:%s@%s>' % (identity.display_name, identity.uri.user, identity.uri.host)


def format_aor(identity):
    return u'%s@%s' % (identity.uri.user, identity.uri.host)


# TODO: these should be configurable
WELCOME = "Welcome to SIPStache, the Ultimate Over Engineered Virtual Mustache Toolkit, send me a file with a picture and you'll get it back moustache-ified!"
IMG_PATH = "/tmp/sipstache"


class SIPStacheApplication(SylkApplication):
    implements(IObserver)

    def start(self):
        self.sessions = {}
        self.transfer_handlers = set()
        NotificationCenter().add_observer(self, name='IncomingFileTransferHandlerGotFile')
        makedirs(IMG_PATH)

    def stop(self):
        self.sessions.clear()
        NotificationCenter().remove_observer(self, name='IncomingFileTransferHandlerGotFile')
        handlers = self.transfer_handlers
        for handler in handlers:
            handler.stop()
        # Cleanup files
        shutil.rmtree(IMG_PATH, True)

    def incoming_session(self, session):
        session.call_id = session._invitation.call_id
        try:
            transfer_stream = (stream for stream in session.proposed_streams if stream.type == 'file-transfer').next()
        except StopIteration:
            pass
        else:
            if transfer_stream.direction == 'recvonly':
                transfer_handler = IncomingFileTransferHandler(session)
                transfer_handler.start()
                log.msg(u'%s is uploading file %s (%s)' % (format_identity(session.remote_identity), transfer_stream.file_selector.name.decode('utf-8'), self.format_file_size(transfer_stream.file_selector.size)))
            else:
                # Pulling files is not supported
                session.reject(488)
            return

        log.msg(u'New incoming session %s from %s' % (session.call_id, format_identity(session.remote_identity)))
        try:
            chat_stream = next(stream for stream in session.proposed_streams if stream.type == 'chat')
        except StopIteration:
            log.msg(u'Session %s rejected: invalid media, only MSRP chat is supported' % session.call_id)
            session.reject(488)
            return
        aor = format_aor(session.remote_identity)
        if aor in self.sessions:
            log.msg(u'Session %s rejected: another session from the same AoR is in progress' % session.call_id)
            session.reject(488)
            return
        NotificationCenter().add_observer(self, sender=session)
        session.accept([chat_stream])
        self.sessions[aor] = session

    def incoming_subscription(self, request, data):
        request.reject(405)

    def incoming_referral(self, request, data):
        request.reject(405)

    def incoming_sip_message(self, request, data):
        request.reject(405)

    @run_in_thread('stache-io')
    def _process_image(self, local_uri, remote_uri, file):
        # Moustache it up!
        new_filename = moustachefy(file.name)
        try:
            file_selector = FileSelector.for_file(new_filename.encode('utf-8'))
        except IOError:
            log.error('Cannot open file %s' % new_filename)
            return
        # Send it!
        self._send_file(local_uri, remote_uri, file_selector)

    @run_in_twisted_thread
    def _send_file(self, local_uri, remote_uri, file_selector):
        handler = OutgoingFileTransferHandler(local_uri, remote_uri, file_selector)
        NotificationCenter().add_observer(self, sender=handler)
        self.transfer_handlers.add(handler)
        handler.start()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPSessionDidStart(self, notification):
        session = notification.sender
        try:
            chat_stream = next(stream for stream in session.streams if stream.type == 'chat')
        except StopIteration:
            # Something bad must have happened
            session.end()
            return
        log.msg('Session %s started' % session.call_id)
        session.chat_stream = chat_stream
        chat_stream.send_message(WELCOME, 'text/plain')
        notification.center.add_observer(self, sender=chat_stream)

    def _NH_SIPSessionDidEnd(self, notification):
        session = notification.sender
        log.msg('Session %s ended' % session.call_id)
        notification.center.remove_observer(self, sender=session)
        # We could get DidEnd even if we never got DidStart
        self.sessions.pop(format_aor(session.remote_identity), None)
        try:
            chat_stream = next(stream for stream in session.streams if stream.type == 'chat')
        except StopIteration:
            pass
        else:
            notification.center.remove_observer(self, sender=chat_stream)

    def _NH_SIPSessionDidFail(self, notification):
        session = notification.sender
        log.msg('Session %s failed' % session.call_id)
        notification.center.remove_observer(self, sender=session)
        del self.sessions[format_identity(session.remote_identity)]

    def _NH_SIPSessionGotProposal(self, notification):
        session = notification.sender
        session.reject_proposal()

    def _NH_SIPSessionDidRenegotiateStreams(self, notification):
        session = notification.sender
        if not session.streams:
            log.msg(u'Session %s has removed all streams, session will be terminated' % session.call_id)
            session.end()

    def _NH_SIPSessionTransferNewIncoming(self, notification):
        notification.sender.reject_transfer(403)

    def _NH_ChatStreamGotMessage(self, notification):
        stream = notification.sender
        message = notification.data.message
        content_type = message.content_type.lower()
        if content_type.startswith('text/'):
            stream.msrp_session.send_report(notification.data.chunk, 200, 'OK')
            stream.send_message('Send me images!', 'text/plain')
        else:
            stream.msrp_session.send_report(notification.data.chunk, 413, 'Unwanted message')

    def _NH_IncomingFileTransferHandlerGotFile(self, notification):
        self._process_image(notification.data.local_uri, notification.data.remote_uri, notification.data.file)

    def _NH_OutgoingFileTransferHandlerDidStart(self, notification):
        pass

    def _NH_OutgoingFileTransferHandlerDidEnd(self, notification):
        handler = notification.sender
        self.transfer_handlers.remove(handler)

    _NH_OutgoingFileTransferHandlerDidFail = _NH_OutgoingFileTransferHandlerDidEnd

    @staticmethod
    def format_file_size(size):
        infinite = float('infinity')
        boundaries = [(             1024, '%d bytes',               1),
                      (          10*1024, '%.2f KB',           1024.0),  (     1024*1024, '%.1f KB',           1024.0),
                      (     10*1024*1024, '%.2f MB',      1024*1024.0),  (1024*1024*1024, '%.1f MB',      1024*1024.0),
                      (10*1024*1024*1024, '%.2f GB', 1024*1024*1024.0),  (      infinite, '%.1f GB', 1024*1024*1024.0)]
        for boundary, format, divisor in boundaries:
            if size < boundary:
                return format % (size/divisor,)
        else:
            return "%d bytes" % size


class File(object):

    def __init__(self, name, hash, size):
        self.name = name
        self.hash = hash
        self.size = size

    @property
    def file_selector(self):
        return FileSelector.for_file(self.name.encode('utf-8'), hash=self.hash)


class IncomingFileTransferHandler(object):
    implements(IObserver)

    def __init__(self, session):
        self.session = session
        self.stream = next(stream for stream in self.session.proposed_streams if stream.type == 'file-transfer' and stream.direction == 'recvonly')
        self.error = False
        self.ended = False
        self.file = None
        self.file_selector = None
        self.filename = None
        self.hash = None
        self.status = None
        self.timer = None
        self.transfer_finished = False

    def start(self):
        self.session.accept([self.stream])
        NotificationCenter().add_observer(self, sender=self.session)

    def _start(self):
        self.file_selector = self.stream.file_selector
        path = IMG_PATH
        makedirs(path)
        self.filename = filename = os.path.join(path, self.file_selector.name.decode('utf-8'))
        basename, ext = os.path.splitext(filename)
        i = 1
        while os.path.exists(filename):
            filename = '%s_%d%s' % (basename, i, ext)
            i += 1
        self.filename = filename
        try:
            self.file = open(self.filename, 'wb')
        except EnvironmentError:
            log.msg('Room %s - cannot write destination filename: %s' % (self.uri, self.filename))
            self.session.end()
            return
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        notification_center.add_observer(self, sender=self.session)
        notification_center.add_observer(self, sender=self.stream)
        self.hash = hashlib.sha1()

    @run_in_thread('file-transfer')
    def write_chunk(self, data):
        notification_center = NotificationCenter()
        if data is not None:
            try:
                self.file.write(data)
            except EnvironmentError, e:
                notification_center.post_notification('IncomingFileTransferHandlerGotError', sender=self, data=NotificationData(error=str(e)))
            else:
                self.hash.update(data)
        else:
            self.file.close()
            if self.error:
                notification_center.post_notification('IncomingFileTransferHandlerDidFail', sender=self)
            else:
                notification_center.post_notification('IncomingFileTransferHandlerDidEnd', sender=self)

    @run_in_thread('file-io')
    def remove_bogus_file(self, filename):
        try:
            os.unlink(filename)
        except OSError:
            pass

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPSessionDidStart(self, notification):
        session = notification.sender
        notification.center.remove_observer(self, sender=session)
        # Observer will be added back on _start
        self._start()

    def _NH_SIPSessionDidFail(self, notification):
        session = notification.sender
        log.msg('File transfer session %s failed' % session.call_id)
        notification.center.remove_observer(self, sender=session)
        self.session = None
        self.stream = None
        # No need to do anything else, since all the processing begins on DidStart

    def _NH_SIPSessionDidEnd(self, notification):
        self.ended = True
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None

        notification.center.remove_observer(self, sender=self.stream)
        notification.center.remove_observer(self, sender=self.session)

        # Mark end of write operation
        self.write_chunk(None)

    def _NH_FileTransferStreamGotChunk(self, notification):
        self.write_chunk(notification.data.content)

    def _NH_FileTransferStreamDidFinish(self, notification):
        self.transfer_finished = True
        if self.timer is None:
            self.timer = reactor.callLater(5, self.session.end)

    def _NH_IncomingFileTransferHandlerGotError(self, notification):
        log.error('Error while handling incoming file transfer: %s' % notification.data.error)
        self.error = True
        self.status = notification.data.error
        if not self.ended and self.timer is None:
            self.timer = reactor.callLater(5, self.session.end)

    def _NH_IncomingFileTransferHandlerDidEnd(self, notification):
        notification.center.remove_observer(self, sender=self)

        remote_hash = self.file_selector.hash
        if not self.transfer_finished:
            log.msg('File transfer of %s cancelled' % os.path.basename(self.filename))
            self.remove_bogus_file(self.filename)
            self.status = 'INCOMPLETE'
        else:
            local_hash = 'sha1:' + ':'.join(re.findall(r'..', self.hash.hexdigest().upper()))
            if local_hash != remote_hash:
                log.warning('Hash of transferred file does not match the remote hash (file may have changed).')
                self.status = 'HASH_MISSMATCH'
                self.remove_bogus_file(self.filename)
            else:
                self.status = 'OK'

        self_uri = SIPURI.new(self.session.local_identity.uri)
        self_uri.parameters.clear()
        sender_uri = SIPURI.new(self.session.remote_identity.uri)
        sender_uri.parameters.clear()

        self.session = None
        self.stream = None

        file = File(self.filename, remote_hash, self.file_selector.size)
        notification.center.post_notification('IncomingFileTransferHandlerGotFile', sender=self, data=NotificationData(local_uri=self_uri, remote_uri=sender_uri, file=file))

    def _NH_IncomingFileTransferHandlerDidFail(self, notification):
        notification.center.remove_observer(self, sender=self)
        self.session = None
        self.stream = None


class InterruptFileTransfer(Exception): pass

class OutgoingFileTransferHandler(object):
    implements(IObserver)

    def __init__(self, sender_uri, destination_uri, file_selector):
        self.sender_uri = sender_uri
        self.destination_uri = destination_uri
        self.file_selector = file_selector
        self.session = None
        self.stream = None
        self.timer = None
        self.success = False

    @run_in_green_thread
    def start(self):
        notification_center = NotificationCenter()
        self.greenlet = api.getcurrent()
        settings = SIPSimpleSettings()
        account = AccountManager().sylkserver_account
        if account.sip.outbound_proxy is not None:
            uri = SIPURI(host=account.sip.outbound_proxy.host,
                         port=account.sip.outbound_proxy.port,
                         parameters={'transport': account.sip.outbound_proxy.transport})
        else:
            uri = self.destination_uri
        lookup = DNSLookup()
        try:
            routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
        except DNSLookupError:
            notification_center.post_notification('OutgoingFileTransferHandlerDidFail', sender=self)
            return

        self.session = Session(account)
        self.stream = FileTransferStream(self.file_selector, 'sendonly')
        notification_center.add_observer(self, sender=self.session)
        notification_center.add_observer(self, sender=self.stream)
        from_header = FromHeader(self.sender_uri, u'SIPStache File Transfer')
        to_header = ToHeader(self.destination_uri)
        transport = routes[0].transport
        parameters = {} if transport=='udp' else {'transport': transport}
        contact_header = ContactHeader(SIPURI(user=self.sender_uri.user, host=SIPConfig.local_ip.normalized, port=getattr(Engine(), '%s_port' % transport), parameters=parameters))
        extra_headers = []
        if ThorNodeConfig.enabled:
            extra_headers.append(Header('Thor-Scope', 'sipstache-file'))
        extra_headers.append(Header('X-Originator-From', str(self.destination_uri)))
        self.session.connect(from_header, to_header, contact_header=contact_header, routes=routes, streams=[self.stream], is_focus=False, extra_headers=extra_headers)
        notification_center.post_notification('OutgoingFileTransferHandlerDidStart', sender=self)

    def stop(self):
        if self.session is not None:
            self.session.end()

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_FileTransferStreamDidFinish(self, notification):
        self.success = True
        if self.timer is None:
            self.timer = reactor.callLater(2, self.session.end)

    def _NH_SIPSessionDidEnd(self, notification):
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None
        notification.center.remove_observer(self, sender=self.stream)
        notification.center.remove_observer(self, sender=self.session)
        self.session = None
        self.stream = None
        if self.success:
            notification.center.post_notification('OutgoingFileTransferHandlerDidFail', sender=self)
        else:
            notification.center.post_notification('OutgoingFileTransferHandlerDidEnd', sender=self)

    _NH_SIPSessionDidFail = _NH_SIPSessionDidEnd

