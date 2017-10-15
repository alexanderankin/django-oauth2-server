import six
import base64
import warnings

from rest_framework.test import APIClient
from rest_framework import status
from django.test import TestCase
from django.utils import timezone

from django.utils.deprecation import (
    RemovedInDjango20Warning, RemovedInDjango110Warning,
)

from apps.tokens.models import (
    OAuthAuthorizationCode,
    OAuthAccessToken,
    OAuthRefreshToken,
)


class AuthorizationCodeTest(TestCase):

    fixtures = [
        'test_credentials',
        'test_scopes',
    ]

    def assertRedirects(self, response, expected_url, status_code=302,
                        target_status_code=200, host=None, msg_prefix='',
                        fetch_redirect_response=True):
        """Asserts that a response redirected to a specific URL, and that the
        redirect URL can be loaded.

        Note that assertRedirects won't work for external links since it uses
        TestClient to do a request (use fetch_redirect_response=False to check
        such links without fetching them).
        """
        if host is not None:
            warnings.warn(
                "The host argument is deprecated and no longer used by assertRedirects",
                RemovedInDjango20Warning, stacklevel=2
            )

        if msg_prefix:
            msg_prefix += ": "

        if hasattr(response, 'redirect_chain'):
            # The request was a followed redirect
            self.assertTrue(len(response.redirect_chain) > 0,
                msg_prefix + "Response didn't redirect as expected: Response"
                " code was %d (expected %d)" %
                    (response.status_code, status_code))

            self.assertEqual(response.redirect_chain[0][1], status_code,
                msg_prefix + "Initial response didn't redirect as expected:"
                " Response code was %d (expected %d)" %
                    (response.redirect_chain[0][1], status_code))

            url, status_code = response.redirect_chain[-1]
            scheme, netloc, path, query, fragment = six.moves.urllib.parse.urlsplit(url)

            self.assertEqual(response.status_code, target_status_code,
                msg_prefix + "Response didn't redirect as expected: Final"
                " Response code was %d (expected %d)" %
                    (response.status_code, target_status_code))

        else:
            # Not a followed redirect
            self.assertEqual(response.status_code, status_code,
                msg_prefix + "Response didn't redirect as expected: Response"
                " code was %d (expected %d)" %
                    (response.status_code, status_code))

            url = response.url
            scheme, netloc, path, query, fragment = six.moves.urllib.parse.urlsplit(url)

            if fetch_redirect_response:
                redirect_response = response.client.get(path, QueryDict(query),
                                                        secure=(scheme == 'https'))

                # Get the redirection page, using the same client that was used
                # to obtain the original response.
                self.assertEqual(redirect_response.status_code, target_status_code,
                    msg_prefix + "Couldn't retrieve redirection page '%s':"
                    " response code was %d (expected %d)" %
                        (path, redirect_response.status_code, target_status_code))

        if url != expected_url:
            # For temporary backwards compatibility, try to compare with a relative url
            e_scheme, e_netloc, e_path, e_query, e_fragment = six.moves.urllib.parse.urlsplit(expected_url)
            relative_url = six.moves.urllib.parse.urlunsplit(('', '', e_path, e_query, e_fragment))
            if url == relative_url:
                warnings.warn(
                    "assertRedirects had to strip the scheme and domain from the "
                    "expected URL, as it was always added automatically to URLs "
                    "before Django 1.9. Please update your expected URLs by "
                    "removing the scheme and domain.",
                    RemovedInDjango20Warning, stacklevel=2)
                expected_url = relative_url

        if url != expected_url:
            urlo = six.moves.urllib.parse.urlparse(url)
            urloq = six.moves.urllib.parse.parse_qs(urlo.query)
            urle = six.moves.urllib.parse.urlparse(expected_url)
            urleq = six.moves.urllib.parse.parse_qs(expected_url.query)

            self.assertDictEqual(urloq, urleq)
            # self.assertEqual(urlo.path, urle.path)

            # determine expected_url without its query
            e_scheme, e_netloc, e_path, e_query, e_fragment = six.moves.urllib.parse.urlsplit(expected_url)
            e_noq = six.moves.urllib.parse.urlunsplit(('', '', e_path, '', e_fragment))

            # determine url without its query
            u_scheme, u_netloc, u_path, u_query, u_fragment = six.moves.urllib.parse.urlsplit(expected_url)
            u_noq = six.moves.urllib.parse.urlunsplit(('', '', u_path, '', u_fragment))

            self.assertEqual(url, expected_url,
                msg_prefix + "Response redirected to '%s', expected '%s'" %
                    (url, expected_url))
        else:
            self.assertEqual(url, expected_url,
                msg_prefix + "Response redirected to '%s', expected '%s'" %
                    (url, expected_url))

    def setUp(self):
        self.api_client = APIClient()

    def test_no_client_id(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        response = self.api_client.get(
            path='/web/authorize/',
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_client')
        self.assertContains(response, u'No client id supplied')

    def test_invalid_client_id(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        response = self.api_client.get(
            path='/web/authorize/?client_id=bogus',
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_client')
        self.assertContains(response, u'The client id supplied is invalid')

    def test_missing_response_type(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        response = self.api_client.get(
            path='/web/authorize/?client_id=testclient',
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_request')
        self.assertContains(response, u'Invalid or missing response type')

    def test_invalid_response_type(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        response = self.api_client.get(
            path='/web/authorize/?client_id=testclient&response_type=bogus',
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_request')
        self.assertContains(response, u'Invalid or missing response type')

    def test_missing_redirect_uri(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        response = self.api_client.get(
            path='/web/authorize/?client_id=testclient&response_type=code',
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_uri')
        self.assertContains(response, u'No redirect URI was supplied or stored')

    def test_missing_state(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        query_string = six.moves.urllib.parse.urlencode({
            'client_id': 'testclient',
            'response_type': 'code',
            'redirect_uri': 'http://www.example.com'
        })
        response = self.api_client.get(
            path='/web/authorize/?{}'.format(query_string),
        )

        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        self.assertContains(response, u'invalid_request')
        self.assertContains(response, u'The state parameter is required')

    def test_success(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        query_string = six.moves.urllib.parse.urlencode({
            'client_id': 'testclient',
            'response_type': 'code',
            'redirect_uri': 'http://www.example.com',
            'state': 'somestate',
        })
        response = self.api_client.post(
            path='/web/authorize/?{}'.format(query_string),
            data={
                'authorize': u'yes',
                'scopes': [u'1', u'2', u'3'],
            },
        )

        auth_code = OAuthAuthorizationCode.objects.last()
        self.assertEqual(auth_code.redirect_uri, 'http://www.example.com')
        self.assertEqual(auth_code.scope, 'foo bar qux')

        self.assertRedirects(
            response,
            'http://www.example.com?state=somestate&code={}'
            .format(auth_code.code),
            fetch_redirect_response=False,
        )

        # Now we should be able to get access token
        self.assertEqual(OAuthAccessToken.objects.count(), 0)
        self.assertEqual(OAuthRefreshToken.objects.count(), 0)

        response = self.api_client.post(
            path='/api/v1/tokens/',
            data={
                'grant_type': 'authorization_code',
                'code': auth_code.code,
            },
            HTTP_AUTHORIZATION='Basic: {}'.format(
                base64.encodestring(six.binary_type('testclient:testpassword', 'utf8'))),
        )

        access_token = OAuthAccessToken.objects.last()
        refresh_token = OAuthRefreshToken.objects.last()

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['id'], access_token.pk)
        self.assertEqual(response.data['access_token'], access_token.access_token)
        self.assertEqual(response.data['expires_in'], 3600)
        self.assertEqual(response.data['token_type'], 'Bearer')
        self.assertEqual(response.data['scope'], 'foo bar qux')
        self.assertEqual(response.data['refresh_token'], refresh_token.refresh_token)

        # Auth code should be deleted once access token is returned
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

    def test_expired_code(self):
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)

        query_string = six.moves.urllib.parse.urlencode({
            'client_id': 'testclient',
            'response_type': 'code',
            'redirect_uri': 'http://www.example.com',
            'state': 'somestate',
        })
        response = self.api_client.post(
            path='/web/authorize/?{}'.format(query_string),
            data={
                'authorize': u'yes',
                'scopes': [u'1', u'2', u'3'],
            },
        )

        auth_code = OAuthAuthorizationCode.objects.last()
        self.assertEqual(auth_code.redirect_uri, 'http://www.example.com')
        self.assertEqual(auth_code.scope, 'foo bar qux')

        self.assertRedirects(
            response,
            'http://www.example.com?state=somestate&code={}'
            .format(auth_code.code),
            fetch_redirect_response=False,
        )

        # Now let's text expired auth code does not allow us to get access token
        auth_code.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        auth_code.save()

        self.assertEqual(OAuthAccessToken.objects.count(), 0)
        self.assertEqual(OAuthRefreshToken.objects.count(), 0)

        response = self.api_client.post(
            path='/api/v1/tokens/',
            data={
                'grant_type': 'authorization_code',
                'code': auth_code.code,
            },
            HTTP_AUTHORIZATION='Basic: {}'.format(
                base64.encodestring(six.binary_type('testclient:testpassword', 'utf8'))),
        )

        self.assertEqual(OAuthAccessToken.objects.count(), 0)
        self.assertEqual(OAuthRefreshToken.objects.count(), 0)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], u'access_denied')
        self.assertEqual(response.data['error_description'],
                         u'Authorization code has expired')

        # Expired auth code should be deleted
        self.assertEqual(OAuthAuthorizationCode.objects.count(), 0)