# -*- coding: utf-8 -*-
#
# Handlerse dealing with submission interface
from __future__ import print_function
import copy
import json
import re

from six import text_type

from globaleaks import models
from globaleaks.handlers.admin.questionnaire import db_get_questionnaire
from globaleaks.handlers.base import BaseHandler
from globaleaks.orm import transact
from globaleaks.rest import errors, requests
from globaleaks.utils.security import hash_password, sha256, generateRandomReceipt
from globaleaks.state import State
from globaleaks.utils.structures import get_localized_values
from globaleaks.utils.token import TokenList
from globaleaks.utils.utility import log, get_expiration, \
    datetime_now, datetime_never, datetime_to_ISO8601


def _parse_request(client_ip, tid):

    if State.tenant_cache[tid]['enable_network_detecting']:

        ext_ip_addr = State.tenant_cache[tid]['external_ip']
        int_ip_addr = State.tenant_cache[tid]['internal_ip']

        extIPoctetNumber = len(ext_ip_addr.split("."))
        intIPoctetNumber = len(int_ip_addr.split("."))

        external_ip_regex = r"(" + State.tenant_cache[tid]['external_ip'] + (".\d{1,3}" * (4-extIPoctetNumber) ) + ")"
        internal_ip_regex = r"(" + State.tenant_cache[tid]['internal_ip'] + (".\d{1,3}" * (4-intIPoctetNumber) ) + ")"

        if re.search(external_ip_regex, client_ip):
            return 1

        if re.search(internal_ip_regex, client_ip):
            return 0

        print("IP NON RICONOSCIUTO !!!")

    return 0


def db_assign_submission_progressive(session, tid):
    counter = session.query(models.Config).filter(models.Config.tid == tid, models.Config.var_name == u'counter_submissions').one()
    counter.value += 1
    return counter.value


def _db_serialize_archived_field_recursively(field, language):

    #if field['sensitive_data'] == True:
    #    print "ho trovato un campo sensibile"
    #    return

    for key, _ in field.get('attrs', {}).items():
        if key not in field['attrs']:
            continue

        if 'type' not in field['attrs'][key]:
            continue

        if field['attrs'][key]['type'] == u'localized':
            if language in field['attrs'][key].get('value', []):
                field['attrs'][key]['value'] = field['attrs'][key]['value'][language]
            else:
                field['attrs'][key]['value'] = ""

    for o in field.get('options', []):
        get_localized_values(o, o, models.FieldOption.localized_keys, language)

    for c in field.get('children', []):
        _db_serialize_archived_field_recursively(c, language)

    return get_localized_values(field, field, models.Field.localized_keys, language)


def db_serialize_archived_questionnaire_schema(session, questionnaire_schema, language):
    questionnaire = copy.deepcopy(questionnaire_schema)

    for step in questionnaire:
        for field in step['children']:
            _db_serialize_archived_field_recursively(field, language)

        get_localized_values(step, step, models.Step.localized_keys, language)


    return questionnaire


def db_serialize_archived_preview_schema(session, preview_schema, language):
    preview = copy.deepcopy(preview_schema)

    for field in preview:
        _db_serialize_archived_field_recursively(field, language)

    return preview


def db_serialize_questionnaire_answers_recursively(session, answers, answers_by_group, groups_by_answer):
    ret = {}

    for answer in answers:
        if answer.is_leaf:
            ret[answer.key] = answer.value
        else:
            ret[answer.key] = [db_serialize_questionnaire_answers_recursively(session, answers_by_group.get(group.id, []), answers_by_group, groups_by_answer)
                                  for group in groups_by_answer.get(answer.id, [])]

    return ret


def db_serialize_questionnaire_answers(session, tid, usertip, internaltip):
    aqs = session.query(models.ArchivedSchema).filter(models.ArchivedSchema.hash == internaltip.questionnaire_hash).one()
    questionnaire = db_serialize_archived_questionnaire_schema(session, aqs.schema, State.tenant_cache[tid].default_language)

    answers = []
    answers_by_group = {}
    groups_by_answer = {}
    all_answers_ids = []
    root_answers_ids = []

    for s in questionnaire:
        for f in s['children']:
            if f['template_id'] == 'whistleblower_identity':
                if isinstance(usertip, models.InternalTip) or \
                   f['attrs']['visibility_subject_to_authorization']['value'] is False or \
                   (isinstance(usertip, models.ReceiverTip) and usertip.can_access_whistleblower_identity):
                    root_answers_ids.append(f['id'])
            else:
                root_answers_ids.append(f['id'])

    for answer in session.query(models.FieldAnswer) \
                       .filter(models.FieldAnswer.internaltip_id == internaltip.id):
        all_answers_ids.append(answer.id)

        if answer.key in root_answers_ids:
            answers.append(answer)

        if answer.fieldanswergroup_id not in answers_by_group:
            answers_by_group[answer.fieldanswergroup_id] = []

        answers_by_group[answer.fieldanswergroup_id].append(answer)

    for group in session.query(models.FieldAnswerGroup) \
                      .filter(models.FieldAnswerGroup.fieldanswer_id.in_(all_answers_ids)) \
                      .order_by(models.FieldAnswerGroup.number):

        if group.fieldanswer_id not in groups_by_answer:
            groups_by_answer[group.fieldanswer_id] = []

        groups_by_answer[group.fieldanswer_id].append(group)

    return db_serialize_questionnaire_answers_recursively(session, answers, answers_by_group, groups_by_answer)


def db_save_questionnaire_answers(session, tid, internaltip_id, entries):
    ret = []

    for key, value in entries.items():
        field_answer = models.FieldAnswer({
            'internaltip_id': internaltip_id,
            'key': key,
            'tid': tid,
        })

        session.add(field_answer)
        session.flush()

        if isinstance(value, list):
            field_answer.is_leaf = False
            field_answer.value = ""
            n = 0
            for elem in value:
                group = models.FieldAnswerGroup({
                  'fieldanswer_id': field_answer.id,
                  'number': n,
                  'tid': tid,
                })

                session.add(group)
                session.flush()

                group_elems = db_save_questionnaire_answers(session, tid, internaltip_id, elem)
                for group_elem in group_elems:
                    group_elem.fieldanswergroup_id = group.id

                n += 1
        else:
            field_answer.is_leaf = True
            field_answer.value = text_type(value)

        ret.append(field_answer)

    return ret


def extract_answers_preview(questionnaire, answers):
    preview = {}

    preview.update({f['id']: copy.deepcopy(answers[f['id']])
        for s in questionnaire for f in s['children'] if f['preview'] and f['id'] in answers})

    return preview


def db_archive_questionnaire_schema(session, questionnaire, questionnaire_hash):
    if session.query(models.ArchivedSchema).filter(models.ArchivedSchema.hash == questionnaire_hash).count():
        return

    aqs = models.ArchivedSchema()
    aqs.hash = questionnaire_hash

    aqs.schema = questionnaire
    aqs.preview = [f for s in questionnaire for f in s['children'] if f['preview']]

    session.add(aqs)


def db_get_itip_receiver_list(session, itip):
    ret = []

    for rtip, user in session.query(models.ReceiverTip, models.User).filter(models.ReceiverTip.internaltip_id == itip.id,
                                                                            models.User.id == models.ReceiverTip.receiver_id):
        ret.append({
            "id": rtip.receiver_id,
            "name": user.name,
            "pgp_key_public": user.pgp_key_public,
            "last_access": datetime_to_ISO8601(rtip.last_access),
            "access_counter": rtip.access_counter,
        })

    return ret


def serialize_itip(session, internaltip, language):
    aq = session.query(models.ArchivedSchema).filter(models.ArchivedSchema.hash == internaltip.questionnaire_hash).one()

    return {
        'id': internaltip.id,
        'creation_date': datetime_to_ISO8601(internaltip.creation_date),
        'update_date': datetime_to_ISO8601(internaltip.update_date),
        'expiration_date': datetime_to_ISO8601(internaltip.expiration_date),
        'progressive': internaltip.progressive,
        'context_id': internaltip.context_id,
        'questionnaire': db_serialize_archived_questionnaire_schema(session, aq.schema, language),
        'receivers': db_get_itip_receiver_list(session, internaltip),
        'https': internaltip.https,
        'enable_two_way_comments': internaltip.enable_two_way_comments,
        'enable_two_way_messages': internaltip.enable_two_way_messages,
        'enable_attachments': internaltip.enable_attachments,
        'enable_whistleblower_identity': internaltip.enable_whistleblower_identity,
        'identity_provided': internaltip.identity_provided,
        'identity_provided_date': datetime_to_ISO8601(internaltip.identity_provided_date),
        'wb_last_access': datetime_to_ISO8601(internaltip.wb_last_access),
        'wb_access_revoked': internaltip.receipt_hash == None,
        'total_score': internaltip.total_score
    }


def serialize_usertip(session, usertip, itip, language, is_sensitive_data_visible=False):
    ret = serialize_itip(session, itip, language)
    ret['id'] = usertip.id
    ret['internaltip_id'] = itip.id
    ret['answers'] = db_serialize_questionnaire_answers(session, itip.tid, usertip, itip)
    ret['sensitive_answers'] = []

    #if False :
    #    if not is_sensitive_data_visible:
    #        obfuscate_sensitive_answers(session, ret['answers'], False)
    #    else:
    #        output_list = extract_sensitive_answers(session, ret['answers'], [], language)
    #        ret['sensitive_answers'] = output_list

    if not is_sensitive_data_visible:
        obfuscate_sensitive_answers(session, ret['answers'], False)
    else:
        output_list = extract_sensitive_answers(session, ret['answers'], [], language)
        ret['sensitive_answers'] = output_list

    return ret

def obfuscate_sensitive_answers(session, answers, to_obfuscate):
    for key in answers.keys():
        string_key = str(key)

        if string_key == 'value' and to_obfuscate:
            answers[string_key] = '********'
            to_obfuscate = False

        field = session.query(models.Field).filter(models.Field.id == key).one_or_none()
        if field is not None:
            if field.sensitive_data == True:
                to_obfuscate = True

        if isinstance(answers[string_key], list):
            for item in answers[string_key]:
                obfuscate_sensitive_answers(session, item, to_obfuscate)

def extract_sensitive_answers(session, answers, output_list, language, field_name=None):
    for key in answers.keys():
        string_key = str(key)

        if string_key == 'value' and field_name is not None:
            #print(str(field_name) + ": " + answers[string_key])
            output_list.insert(0, str(field_name) + ": " + answers[string_key])
            field_name = None

        field = session.query(models.Field).filter(models.Field.id == key).one_or_none()
        if field is not None:
            if field.sensitive_data:
                field_name = field.label[language]

        if isinstance(answers[string_key], list):
            for item in answers[string_key]:
                extract_sensitive_answers(session, item, output_list, language, field_name)

    return output_list


def db_create_receivertip(session, receiver, internaltip):
    """
    Create models.ReceiverTip for the required tier of models.Receiver.
    """
    log.debug("Creating receivertip for receiver: %s", receiver.id)

    receivertip = models.ReceiverTip()
    receivertip.internaltip_id = internaltip.id
    receivertip.receiver_id = receiver.id

    session.add(receivertip)


def db_create_submission(session, tid, client_ip, request, uploaded_files, client_using_tor):
    answers = request['answers']

    context, questionnaire = session.query(models.Context, models.Questionnaire) \
                                    .filter(models.Context.id == request['context_id'],
                                            models.Questionnaire.id == models.Context.questionnaire_id,
                                            models.Questionnaire.tid.in_(set([1, tid]))).one_or_none()
    if not context:
        raise errors.ModelNotFound(models.Context)

    steps = db_get_questionnaire(session, tid, questionnaire.id, None)['steps']
    questionnaire_hash = text_type(sha256(json.dumps(steps)))
    db_archive_questionnaire_schema(session, steps, questionnaire_hash)

    submission = models.InternalTip()
    submission.tid = tid

    submission.progressive = db_assign_submission_progressive(session, tid)

    if context.tip_timetolive > -1:
        submission.expiration_date = get_expiration(context.tip_timetolive)
    else:
        submission.expiration_date = datetime_never()

    # this is get from the client as it the only possibility possible
    # that would fit with the end to end submission.
    # the score is only an indicator and not a critical information so we can accept to
    # be fooled by the malicious user.
    submission.total_score = request['total_score']

    # The status https is used to keep track of the security level adopted by the whistleblower
    submission.https = not client_using_tor

    submission.context_id = context.id
    submission.enable_two_way_comments = context.enable_two_way_comments
    submission.enable_two_way_messages = context.enable_two_way_messages
    submission.enable_attachments = context.enable_attachments

    whistleblower_identity = session.query(models.Field) \
                                    .filter(models.Field.template_id == u'whistleblower_identity',
                                            models.Field.step_id == models.Step.id,
                                            models.Step.questionnaire_id == context.questionnaire_id).one_or_none()

    submission.enable_whistleblower_identity = whistleblower_identity is not None

    if submission.enable_whistleblower_identity and request['identity_provided']:
        submission.identity_provided = True
        submission.identity_provided_date = datetime_now()

    submission.questionnaire_hash = questionnaire_hash
    submission.preview = extract_answers_preview(steps, answers)

    receipt = text_type(generateRandomReceipt())

    submission.receipt_hash = hash_password(receipt, State.tenant_cache[tid].receipt_salt)

    #aggiungo il campo ext_network_prov
    #TODO: aggiornare con la logica implementata
    submission.ext_network_prov = _parse_request(client_ip, tid)

    session.add(submission)
    session.flush()

    db_save_questionnaire_answers(session, tid, submission.id, answers)

    for filedesc in uploaded_files:
        new_file = models.InternalFile()
        new_file.tid = tid
        new_file.name = filedesc['name']
        new_file.description = ""
        new_file.content_type = filedesc['type']
        new_file.size = filedesc['size']
        new_file.internaltip_id = submission.id
        new_file.submission = filedesc['submission']
        new_file.filename = filedesc['filename']
        session.add(new_file)
        log.debug("=> file associated %s|%s (%d bytes)",
                  new_file.name, new_file.content_type, new_file.size)

    if context.maximum_selectable_receivers > 0 and \
                    len(request['receivers']) > context.maximum_selectable_receivers:
        raise errors.InputValidationError("selected an invalid number of recipients")

    rtips_count = 0
    for receiver, user in session.query(models.Receiver, models.User) \
                                 .filter(models.Receiver.id.in_(request['receivers']),
                                         models.ReceiverContext.receiver_id == models.Receiver.id,
                                         models.ReceiverContext.context_id == context.id,
                                         models.User.id == models.Receiver.id,
                                         models.User.tid == tid):
        if user.pgp_key_public or State.tenant_cache[tid].allow_unencrypted:
            db_create_receivertip(session, receiver, submission)
            rtips_count += 1

    if rtips_count == 0:
        raise errors.InputValidationError("need at least one recipient")

    log.debug("The finalized submission had created %d models.ReceiverTip(s)", rtips_count)

    return {'receipt': receipt}


@transact
def create_submission(session, tid, client_ip, request, uploaded_files, client_using_tor):
    return db_create_submission(session, tid, client_ip, request, uploaded_files, client_using_tor)


class SubmissionInstance(BaseHandler):
    """
    The interface that creates, populates and finishes a submission.
    """
    check_roles = 'unauthenticated'

    def put(self, token_id):
        """
        Finalize the submission
        """
        request = self.validate_message(self.request.content.read(), requests.SubmissionDesc)

        # The get and use method will raise if the token is invalid
        token = TokenList.get(token_id)
        token.use()

        submission = create_submission(self.request.tid,
                                       self.request.client_ip,
                                       request,
                                       token.uploaded_files,
                                       self.request.client_using_tor)

        # Delete the token only when a valid submission has been stored in the DB
        TokenList.delete(token_id)

        return submission
