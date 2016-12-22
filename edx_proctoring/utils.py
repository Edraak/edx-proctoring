"""
Helpers for the HTTP APIs
"""

import pytz
import logging
from datetime import datetime, timedelta

from django.utils.translation import ugettext as _, pgettext, ungettext
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from edx_proctoring.models import (
    ProctoredExamStudentAttempt,
    ProctoredExamStudentAttemptHistory,
)
from edx_proctoring import constants
from edx_proctoring.runtime import get_runtime_service

log = logging.getLogger(__name__)


class AuthenticatedAPIView(APIView):
    """
    Authenticate APi View.
    """
    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated,)


def get_time_remaining_for_attempt(attempt):
    """
    Returns the remaining time (in seconds) on an attempt
    """

    # returns 0 if the attempt has not been started yet.
    if attempt['started_at'] is None:
        return 0

    # need to adjust for allowances
    expires_at = attempt['started_at'] + timedelta(minutes=attempt['allowed_time_limit_mins'])
    now_utc = datetime.now(pytz.UTC)

    if expires_at > now_utc:
        time_remaining_seconds = (expires_at - now_utc).seconds
    else:
        time_remaining_seconds = 0

    return time_remaining_seconds


def humanized_time(time_in_minutes):
    """
    Converts the given value in minutes to a more human readable format
    1 -> 1 Minute
    2 -> 2 Minutes
    60 -> 1 hour
    90 -> 1 hour and 30 Minutes
    120 -> 2 hours
    """
    hours = int(time_in_minutes / 60)
    minutes = time_in_minutes % 60
    display = ""

    if hours > 0:
        display+=ungettext("{num_of_hours} hour", "{num_of_hours} hours", hours).format(num_of_hours=hours)
    if minutes > 0:
        if display != '':
            display+=_(" and ")
        display+=ungettext("{num_of_minutes} minute", "{num_of_minutes} minutes", minutes).format(num_of_minutes=minutes)
    return display


def locate_attempt_by_attempt_code(attempt_code):
    """
    Helper method to look up an attempt by attempt_code. This can be either in
    the ProctoredExamStudentAttempt *OR* ProctoredExamStudentAttemptHistory tables
    we will return a tuple of (attempt, is_archived_attempt)
    """
    attempt_obj = ProctoredExamStudentAttempt.objects.get_exam_attempt_by_code(attempt_code)

    is_archived_attempt = False
    if not attempt_obj:
        # try archive table
        attempt_obj = ProctoredExamStudentAttemptHistory.get_exam_attempt_by_code(attempt_code)
        is_archived_attempt = True

        if not attempt_obj:
            # still can't find, error out
            err_msg = (
                'Could not locate attempt_code: {attempt_code}'.format(attempt_code=attempt_code)
            )
            log.error(err_msg)

    return (attempt_obj, is_archived_attempt)


def has_client_app_shutdown(attempt):
    """
    Returns True if the client app has shut down, False otherwise
    """

    # we never heard from the client, so it must not have started
    if not attempt['last_poll_timestamp']:
        return True

    elapsed_time = (datetime.now(pytz.UTC) - attempt['last_poll_timestamp']).total_seconds()
    return elapsed_time > constants.SOFTWARE_SECURE_SHUT_DOWN_GRACEPERIOD


def emit_event(exam, event_short_name, attempt=None, override_data=None):
    """
    Helper method to emit an analytics event
    """

    exam_type = (
        'timed' if not exam['is_proctored'] else
        ('practice' if exam['is_practice_exam'] else 'proctored')
    )

    # establish baseline schema for event 'context'
    context = {
        'course_id': exam['course_id']
    }

    # establish baseline schema for event 'data'
    data = {
        'exam_id': exam['id'],
        'exam_content_id': exam['content_id'],
        'exam_name': exam['exam_name'],
        'exam_default_time_limit_mins': exam['time_limit_mins'],
        'exam_is_proctored': exam['is_proctored'],
        'exam_is_practice_exam': exam['is_practice_exam'],
        'exam_is_active': exam['is_active']
    }

    if attempt:
        # if an attempt is passed in then use that to add additional baseline
        # schema elements

        # let's compute the relative time we're firing the event
        # compared to the start time, if the attempt has already started.
        # This can be used to determine how far into an attempt a given
        # event occured (e.g. "time to complete exam")
        attempt_event_elapsed_time_secs = (
            (datetime.now(pytz.UTC) - attempt['started_at']).seconds if attempt['started_at'] else
            None
        )

        attempt_data = {
            'attempt_id': attempt['id'],
            'attempt_user_id': attempt['user']['id'],
            'attempt_started_at': attempt['started_at'],
            'attempt_completed_at': attempt['completed_at'],
            'attempt_code': attempt['attempt_code'],
            'attempt_allowed_time_limit_mins': attempt['allowed_time_limit_mins'],
            'attempt_status': attempt['status'],
            'attempt_event_elapsed_time_secs': attempt_event_elapsed_time_secs
        }
        data.update(attempt_data)
        name = '.'.join(['edx', 'special-exam', exam_type, 'attempt', event_short_name])
    else:
        name = '.'.join(['edx', 'special-exam', exam_type, event_short_name])

    # allow caller to override event data
    if override_data:
        data.update(override_data)

    service = get_runtime_service('analytics')
    if service:
        service.emit_event(name, context, data)
    else:
        log.warn('Analytics event service not configured. If this is a production environment, please resolve.')
