# -*- coding: utf-8 -*-
#
# Handlers dealing with platform authentication
import ipaddress

from os import urandom
from random import SystemRandom
from six import text_type
from sqlalchemy import func
from twisted.internet.defer import inlineCallbacks, returnValue

from globaleaks import models
from globaleaks.utils import security
from globaleaks.handlers.base import BaseHandler, Sessions, new_session, new_session_rec_auth
from globaleaks.models import InternalTip, User, Receiver, ReceiverAuthCode
from globaleaks.orm import transact
from globaleaks.rest import errors, requests
from globaleaks.settings import Settings
from globaleaks.state import State as mystate
from globaleaks.utils.utility import datetime_now, is_expired, deferred_sleep, log, parse_csv_ip_ranges_to_ip_networks


AUTH_CODE_EXPIRATION_IN_MINUTES = 30


def random_login_delay():
    """
    in case of failed_login_attempts introduces
    an exponential increasing delay between 0 and 42 seconds

        the function implements the following table:
            ----------------------------------
           | failed_attempts |      delay     |
           | x < 5           | 0              |
           | 5               | random(5, 25)  |
           | 6               | random(6, 36)  |
           | 7               | random(7, 42)  |
           | 8 <= x <= 42    | random(x, 42)  |
           | x > 42          | 42             |
            ----------------------------------
    """
    failed_attempts = Settings.failed_login_attempts

    if failed_attempts >= 5:
        n = failed_attempts * failed_attempts

        min_sleep = failed_attempts if failed_attempts < 42 else 42
        max_sleep = n if n < 42 else 42

        return SystemRandom().randint(min_sleep, max_sleep)

    return 0


def db_get_wbtip_by_receipt(session, tid, receipt):
    hashed_receipt = security.hash_password(receipt, mystate.tenant_cache[tid].receipt_salt)
    return session.query(InternalTip) \
                  .filter(InternalTip.receipt_hash == text_type(hashed_receipt, 'utf-8'),
                          InternalTip.tid == tid).one_or_none()


def generate_authcode_password(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")

    #vogliamo una password composta di soli carattteri numerici
    #chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    chars = "0123456789"
    return ''.join(chars[ord(c) % len(chars)] for c in urandom(length))


@transact
def login_whistleblower(session, tid, receipt, client_using_tor):
    """
    login_whistleblower returns the InternalTip.id
    """
    wbtip = db_get_wbtip_by_receipt(session, tid, receipt)
    if wbtip is None:
        log.debug("Whistleblower login: Invalid receipt")
        Settings.failed_login_attempts += 1
        raise errors.InvalidAuthentication

    if not client_using_tor and not mystate.tenant_cache[tid]['https_whistleblower']:
        log.err("Denied login request over clear Web for role 'whistleblower'")
        raise errors.TorNetworkRequired

    log.debug("Whistleblower login: Valid receipt")

    wbtip.last_access = datetime_now()

    return wbtip.id


@transact
def login(session, tid, username, password, receiver_second_login, receiver_auth_code, client_using_tor, client_ip, token=''):
    """
    login returns a tuple (user_id, state, role, pcn, authCodePrepared)
    """
    if token:
        user = session.query(User).filter(User.auth_token == token, \
                                          User.state != u'disabled', \
                                          User.tid == tid).one_or_none()
    else:
        user = session.query(User).filter(User.username == username, \
                                          User.state != u'disabled', \
                                          User.tid == tid).one_or_none()

    if user is None or (not token and not security.check_password(password, user.salt, user.password)):
        log.debug("Login: Invalid credentials")
        Settings.failed_login_attempts += 1
        raise errors.InvalidAuthentication

    if not client_using_tor and not mystate.tenant_cache[tid]['https_' + user.role]:
        log.err("Denied login request over Web for role '%s'" % user.role)
        raise errors.TorNetworkRequired

    # Check if we're doing IP address checks today
    if mystate.tenant_cache[tid]['ip_filter_authenticated_enable']:
        ip_networks = parse_csv_ip_ranges_to_ip_networks(
            mystate.tenant_cache[tid]['ip_filter_authenticated']
        )
        client_ip = text_type(client_ip)
        client_ip_obj = ipaddress.ip_address(client_ip)

        # Safety check, we always allow localhost to log in
        success = False
        if client_ip_obj.is_loopback is True:
            success = True

        for ip_network in ip_networks:
            if client_ip_obj in ip_network:
                success = True

        if success is not True:
            raise errors.AccessLocationInvalid

    # se sono arrivato qui il primo login � andato a buon fine
    # il login (username, password) per un ricevente viene rieseguito anche al secondo passaggio
    # per motivi di sicurezza
    # A QUESTO PUNTO:
       # SE receiver2ndStepLoginState = 'N':
            # 1 - genero il codice
            # 2 - memorizzo record in ReceiverAuthCode
            # 3 - invio mail
        # ELSE:
            # verifico la correttenza del secondo codice
    if user.role == 'receiver':

        receiver = session.query(Receiver).filter(Receiver.id == user.id).one_or_none()

        if receiver.two_step_login_enabled and not user.password_change_needed:

            if receiver_second_login == 'first_login_to_complete':

                yyyy = str(datetime_now().year)
                mm = str(datetime_now().month).zfill(2)
                dd = str(datetime_now().day).zfill(2)
                result_query = session.query(ReceiverAuthCode).filter(ReceiverAuthCode.receiver_id == user.id,
                                                               func.strftime("%Y-%m-%d", ReceiverAuthCode.creation_date) == yyyy+'-'+mm+'-'+dd).all()

                # genero il codice
                #chiamo la funzione generate_authcode_password che genera la password con l'utilizzo della funzione os.urandom
                #randnum = ''.join(["%s" % SystemRandom().randint(0, 9) for num in range(0, 12)])
                randnum = generate_authcode_password(12)

                #print randnum
                log.debug(randnum[0:4] + ' ' + randnum[4:8] + ' ' + randnum[8:12])


                # inserisco il record nel db
                newAuthCode = models.ReceiverAuthCode()
                newAuthCode.receiver_id = receiver.id

                newAuthCode.salt = security.generateRandomSalt()
                newAuthCode.auth_code = security.hash_password(randnum, newAuthCode.salt)

                session.add(newAuthCode)
                session.flush()

                # invio i tre pezzi del codice alle tre mail specificate nel profilo del ricevente
                email_prg = str(len(result_query)+1)
                day = dd+'/'+mm+'/'+yyyy
                mystate.sendmail(1, receiver.control_mail_1, "Receiver Auth Code #"+email_prg+" - "+day, randnum[0:4])
                mystate.sendmail(1, receiver.control_mail_2, "Receiver Auth Code #"+email_prg+" - "+day, randnum[4:8])
                mystate.sendmail(1, receiver.control_mail_3, "Receiver Auth Code #"+email_prg+" - "+day, randnum[8:12])

                log.debug("Invio delle mail effettuato con successo")

                receiver_second_login = 'second_login_to_complete'

            elif receiver_second_login == 'second_login_to_complete':
                auth_code_item = session.query(ReceiverAuthCode).filter(ReceiverAuthCode.receiver_id == user.id) \
                                                                .order_by(ReceiverAuthCode.creation_date.desc()).first()

                # se non sono passati TOT minuti dall'ultimo codice emesso si può controllare la validità del codice
                if auth_code_item is not None and auth_code_item.is_valid and not is_expired(auth_code_item.creation_date, 0,
                                                                 AUTH_CODE_EXPIRATION_IN_MINUTES, 0, 0):

                    # qui devo verificare che il codice inviato dall'utente sia uguale a una delle permutazioni dei tre blocchi
                    # da quattro cifre che si ottengono dal codice salvato sul db
                    firstBlock  = receiver_auth_code[0:4]
                    secondBlock = receiver_auth_code[4:8]
                    thirdBlock  = receiver_auth_code[8:12]
                    combList = []
                    combList.insert(0, firstBlock + secondBlock + thirdBlock)
                    combList.insert(1, firstBlock + thirdBlock + secondBlock)
                    combList.insert(2, secondBlock + firstBlock + thirdBlock)
                    combList.insert(3, secondBlock + thirdBlock + firstBlock)
                    combList.insert(4, thirdBlock + firstBlock + secondBlock)
                    combList.insert(5, thirdBlock + secondBlock + firstBlock)

                    auth_code_match = False
                    for authCode in combList:
                        if security.check_password(authCode, auth_code_item.salt, auth_code_item.auth_code):
                            auth_code_match = True

                            # POSSO ANCHE FARE UNA UPDATE del campo is_valid PER IL RECORD UTILIZZATO NELLA VALIDAZIONE
                            auth_code_item.is_valid = False
                            session.add(auth_code_item)
                            session.flush()

                            #objs = session.query(ReceiverAuthCode).filter(ReceiverAuthCode.receiver_id == auth_code_item.receiver_id) \
                            #                                      .order_by(ReceiverAuthCode.creation_date.desc(), ReceiverAuthCode.daily_prg.desc())
                            #for obj in objs:
                            #    session.delete(obj)
                            #    session.flush()
                            #session.delete(auth_code_item)

                            receiver_second_login = 'login_ok'
                            break

                    if not auth_code_match:
                        log.debug("Login: Invalid authentication code")
                        Settings.failed_login_attempts += 1
                        raise errors.InvalidAuthentication

                else:
                    log.debug("Login: authentication code is expired. Please repeat login")
                    Settings.failed_login_attempts += 1
                    raise errors.InvalidAuthentication

            else:
                log.debug("receiver_auth_code diverso da first_login_to_complete e second_login_to_complete")
                receiver_second_login = 'login_ok'
        else:
            receiver_second_login = 'login_ok'   #da tenere sotto controllo

    else:
        receiver_second_login = 'login_ok'  # da tenere sotto controllo

    log.debug("Login: Success (%s)" % user.role)

    
    user.last_login = datetime_now()

    return user.id, user.state, user.role, user.password_change_needed, receiver_second_login


class AuthenticationHandler(BaseHandler):
    """
    Login handler for admins and recipents and custodians
    """
    check_roles = 'unauthenticated'
    uniform_answer_time = True

    @inlineCallbacks
    def post(self):
        request = self.validate_message(self.request.content.read(), requests.AuthDesc)

        delay = random_login_delay()
        if delay:
            yield deferred_sleep(delay)

        user_id, status, role, pcn, login_step = yield login(self.request.tid,
                                                 request['username'],
                                                 request['password'],
                                                 request['receiver_second_login'],
                                                 request['receiver_auth_code'],
                                                 self.request.client_using_tor,
                                                 self.request.client_ip,
                                                 request['token'])

        if role == 'receiver' and login_step == 'second_login_to_complete':
            session = new_session_rec_auth(self.request.tid, user_id, role, status, login_step)
            returnValue({
                'session_id': session.id,
                'role': session.user_role,
                'user_id': session.user_id,
                'session_expiration': 1,
                'status': session.user_status,
                'password_change_needed': pcn,
                'receiverLoginState': login_step
            })

        else:
            session = new_session(self.request.tid, user_id, role, status, login_step)
            returnValue({
                'session_id': session.id,
                'role': session.user_role,
                'user_id': session.user_id,
                'session_expiration': int(session.getTime()),
                'status': session.user_status,
                'password_change_needed': pcn,
                'receiverLoginState': login_step
            })



class ReceiptAuthHandler(BaseHandler):
    """
    Receipt handler used by whistleblowers
    """
    check_roles = 'unauthenticated'
    uniform_answer_time = True

    @inlineCallbacks
    def post(self):
        request = self.validate_message(self.request.content.read(), requests.ReceiptAuthDesc)

        receipt = request['receipt']

        delay = random_login_delay()
        if delay:
            yield deferred_sleep(delay)

        user_id = yield login_whistleblower(self.request.tid, receipt, self.request.client_using_tor)

        session = new_session(self.request.tid, user_id, 'whistleblower', 'Enabled', '')

        returnValue({
            'session_id': session.id,
            'role': session.user_role,
            'user_id': session.user_id,
            'session_expiration': int(session.getTime())
        })


class SessionHandler(BaseHandler):
    """
    Session handler for authenticated users
    """
    check_roles = {'admin','receiver','custodian','whistleblower'}

    def get(self):
        """
        Refresh and retrieve session
        """
        return {
            'session_id': self.current_user.id,
            'role': self.current_user.user_role,
            'user_id': self.current_user.user_id,
            'session_expiration': int(self.current_user.getTime()),
            'status': self.current_user.user_status,
            'password_change_needed': False,
            'receiverLoginState': 'first_login_to_complete'
        }

    def delete(self):
        """
        Logout
        """
        del Sessions[self.current_user.id]
