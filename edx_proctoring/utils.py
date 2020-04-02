"""
Helpers for the HTTP APIs
"""

from __future__ import absolute_import

from datetime import datetime, timedelta
import logging
import pytz

from django.utils.translation import ugettext as _

from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError

from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from eventtracking import tracker

from edx_proctoring.models import (
    ProctoredExamStudentAttempt,
    ProctoredExamStudentAttemptHistory,
)

log = logging.getLogger(__name__)


class SessionAuthenticationAllowInactiveUser(SessionAuthentication):
    """Ensure that the user is logged in, but do not require the account to be active.

    We use this in the special case that a user has created an account,
    but has not yet activated it.  We still want to allow the user to
    enroll in courses, so we remove the usual restriction
    on session authentication that requires an active account.

    You should use this authentication class ONLY for end-points that
    it's safe for an un-activated user to access.  For example,
    we can allow a user to update his/her own enrollments without
    activating an account.

    """
    def authenticate(self, request):
        """Authenticate the user, requiring a logged-in account and CSRF.

        This is exactly the same as the `SessionAuthentication` implementation,
        with the `user.is_active` check removed.

        Args:
            request (HttpRequest)

        Returns:
            Tuple of `(user, token)`

        Raises:
            PermissionDenied: The CSRF token check failed.

        """
        # Get the underlying HttpRequest object
        request = request._request  # pylint: disable=protected-access
        user = getattr(request, 'user', None)

        # Unauthenticated, CSRF validation not required
        # This is where regular `SessionAuthentication` checks that the user is active.
        # We have removed that check in this implementation.
        # But we added a check to prevent anonymous users since we require a logged-in account.
        if not user or user.is_anonymous:
            return None

        self.enforce_csrf(request)

        # CSRF passed with authenticated user
        return (user, None)


class AuthenticatedAPIView(APIView):
    """
    Authenticate APi View.
    """
    authentication_classes = (SessionAuthenticationAllowInactiveUser,)
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
        time_remaining_seconds = (expires_at - now_utc).total_seconds()
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

    hours_present = False
    if hours == 0:
        hours_present = False
        template = ""
    elif hours == 1:
        template = _("{num_of_hours} hour")
        hours_present = True
    elif hours >= 2:
        template = _("{num_of_hours} hours")
        hours_present = True
    else:
        template = "error"

    if template != "error":
        if minutes == 0:
            if not hours_present:
                template = _("{num_of_minutes} minutes")
        elif minutes == 1:
            if hours_present:
                template += _(" and {num_of_minutes} minute")
            else:
                template += _("{num_of_minutes} minute")
        else:
            if hours_present:
                template += _(" and {num_of_minutes} minutes")
            else:
                template += _("{num_of_minutes} minutes")

    human_time = template.format(num_of_hours=hours, num_of_minutes=minutes)
    return human_time


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
            (datetime.now(pytz.UTC) - attempt['started_at']).total_seconds() if attempt['started_at'] else
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
        name = '.'.join(['edx', 'special_exam', exam_type, 'attempt', event_short_name])
    else:
        name = '.'.join(['edx', 'special_exam', exam_type, event_short_name])

    # allow caller to override event data
    if override_data:
        data.update(override_data)

    _emit_event(name, context, data)


def _emit_event(name, context, data):
    """
    Do the actual integration into the event-tracker
    """

    try:
        if context:
            # try to parse out the org_id from the course_id
            if 'course_id' in context:
                try:
                    course_key = CourseKey.from_string(context['course_id'])
                    context['org_id'] = course_key.org
                except InvalidKeyError:
                    # leave org_id blank
                    pass

            with tracker.get_tracker().context(name, context):
                tracker.emit(name, data)
        else:
            # if None is passed in then we don't construct the 'with' context stack
            tracker.emit(name, data)
    except KeyError:
        # This happens when a default tracker has not been registered by the host application
        # aka LMS. This is normal when running unit tests in isolation.
        log.warning(
            'Analytics tracker not properly configured. '
            'If this message appears in a production environment, please investigate'
        )
