import 'dart:io';
import 'dart:convert';
import 'package:postgres/postgres.dart';
import 'dart:core';
import 'package:googleapis/people/v1.dart' as peeps;
import 'package:crypto/crypto.dart' as crypto;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:mutex/mutex.dart';

class GoogleAuthentication {
  String deviceKey;
  String state; // a salted hash of deviceKey to match redirects
  bool complete = false;
  oauth2.AuthorizationCodeGrant oauth2libObject;
  oauth2.Client authenticatedClient;
  HttpRequest authWaitRequest;
  Mutex mutex = Mutex();
  GoogleAuthentication(this.deviceKey) {
    state = crypto.sha256.convert(utf8.encode(deviceKey)).toString();
  }
}

// deviceKey, [authgrant, authcomplete]
final List<GoogleAuthentication> auths = [];

const baseUrl = 'jec226.user.srcf.net';

String clientId;
String clientSecret;

Future main() async {
  const ccPath = '../client_credentials.json';
  var clientCredentials = jsonDecode(await File(ccPath).readAsString());
  clientId = clientCredentials['id'];
  clientSecret = clientCredentials['secret'];
  var server = await HttpServer.bind(
    InternetAddress.loopbackIPv4,
    58263,
  );
  print('Listening on localhost:${server.port}');

  const pgcPath = '../postgres_credentials.json';
  var pgc = jsonDecode(await File(pgcPath).readAsString());
  var pgConnection = PostgreSQLConnection('localhost', 5432, 'jec226',
      username: pgc['username'], password: pgc['password']);
  await pgConnection.open();

  await for (HttpRequest request in server) {
    print(request.uri);
    switch (request.method) {
      case 'GET':
        PostgreSQLResult result;
        switch (request.uri.path) {
          case '/owner':
            result = await pgConnection.query(
                'SELECT * FROM test_table WHERE owner LIKE \'%${request.uri.queryParameters['owner']}%\'');
            var listlist = result.map((row) => row.toList()).toList();
            request.response.write(jsonEncode(listlist));
            await request.response.close();
            break;
          case '/all':
            result = await pgConnection.query('SELECT * FROM test_table');
            var listlist = result.map((row) => row.toList()).toList();
            request.response.write(jsonEncode(listlist));
            await request.response.close();
            break;
          case '/profile':
            var deviceKey = request.uri.queryParameters['device_key'];
            var auth = auths.singleWhere((e) => e.deviceKey == deviceKey,
                orElse: () => null);
            if (auth == null) {
              await complain(request, 'No deviceKey $deviceKey authenticated.');
              break;
            }
            var peepsApi = peeps.PeopleApi(auth.authenticatedClient);
            var userPerson = await peepsApi.people
                .get('people/me', personFields: 'names,emailAddresses');
            request.response.write(jsonEncode({
              'name': userPerson.names[0].displayName,
              'email': userPerson.emailAddresses[0].value
            }));
            await request.response.close();
            break;
          case '/auth/google/authreq':
            googleAuthReq(request);
            break;
          case '/auth/google/authgrant': // i.e. redirectUrl
            googleAuthGrant(request);
            break;
          case '/auth/key':
            var deviceKey = request.uri.queryParameters['device_key'];
            var auth = auths.singleWhere((e) => e.deviceKey == deviceKey,
                orElse: () => null);
            request.response
                .write((auth == null || !auth.complete) ? 'invalid' : 'valid');
            await request.response.close();
            break;
          case '/authwait':
            authWaitRequest(request);
            break;
          default:
            await complain(request, 'Unrecognized path.');
        }
        break;
      case 'POST':
        var params;
        await request.listen((event) =>
            params = Uri.splitQueryString(String.fromCharCodes(event)));
        switch (request.uri.path) {
          case '/insert':
            if (!(params.containsKey('owner') &&
                params.containsKey('content'))) {
              await complain(request, 'No entry described for insertion');
            } else {
              await pgConnection.execute(
                  'INSERT INTO test_table VALUES (@ownerParam, @contentParam)',
                  substitutionValues: {
                    'ownerParam': params['owner'],
                    'contentParam': params['content']
                  });
              await request.response.close();
            }
            break;
          case '/delete':
            if (!(params.containsKey('owner') &&
                params.containsKey('content'))) {
              await complain(request, 'No entry specified for deletion');
            } else {
              await pgConnection.execute(
                  'DELETE FROM test_table WHERE owner = @ownerParam AND content = @contentParam',
                  substitutionValues: {
                    'ownerParam': params['owner'],
                    'contentParam': params['content']
                  });
              await request.response.close();
            }
            break;
          case '/clear':
            if (!params.containsKey('owner')) {
              await complain(request, 'No owner supplied to clear request.');
            } else {
              await pgConnection.execute(
                  'DELETE FROM test_table WHERE owner = @ownerParam',
                  substitutionValues: {'ownerParam': params['owner']});
              await request.response.close();
            }
            break;
          case '/clearall':
            await pgConnection.execute('DELETE FROM test_table');
            await request.response.close();
            break;
          default:
            await complain(request, 'Unrecognized POST path');
        }
    }
  }
}

Future<void> complain(HttpRequest request, String complaint) async {
  request.response.statusCode = HttpStatus.badRequest;
  request.response.write(complaint);
  await request.response.close();
}

void googleAuthReq(HttpRequest request) async {
  var deviceKey = request.uri.queryParameters['device_key'];
  var auth = GoogleAuthentication(deviceKey);
  auths.add(auth);

  var authgrantEndpoint = Uri.https('accounts.google.com', 'o/oauth2/v2/auth');
  var redirectUrl = Uri.https(baseUrl, 'servertest/auth/google/authgrant');
  var tokenEndpoint = Uri.https('oauth2.googleapis.com', 'token');
  var scopes = ['profile', 'email'];

  auth.oauth2libObject = oauth2.AuthorizationCodeGrant(
      clientId, authgrantEndpoint, tokenEndpoint,
      secret: clientSecret);
  request.response.write(auth.oauth2libObject
      .getAuthorizationUrl(redirectUrl, scopes: scopes, state: auth.state));
  await request.response.close();
}

void googleAuthGrant(HttpRequest request) async {
  // Find the authentication process the authgrant corresponds to, and acquire
  // its mutex
  var state = request.uri.queryParameters['state'];
  var auth = auths.singleWhere((e) => e.state == state, orElse: () => null);
  if (auth == null) {
    throw Exception('Authorization granted but for an unrecognized app token.');
  }
  await auth.mutex.acquire();
  auth.complete = true;
  auth.authenticatedClient = await auth.oauth2libObject
      .handleAuthorizationResponse(request.uri.queryParameters);
  if (auth.authWaitRequest != null) {
    await auth.authWaitRequest.response.close();
    print('authWaitRequest closed (waited for authgrant).');
  }
  auth.mutex.release();
  request.response.write('Authentication successful');
  await request.response.close();
  /*
  var queryParams = request.uri.queryParameters;
  if (queryParams.containsKey('error')) {
    throw Exception('Authorization failed: error: ${queryParams['error']}');
  }
  var authorizationCode = queryParams['code'];
  // tokreq and tokgrant are handled by Google API :)
  final clientId =
      auth.ClientId(clientCredentials['id'], clientCredentials['secret']);
  var baseClient = http.Client();
  var accessCredentials = await auth.obtainAccessCredentialsViaCodeExchange(
      baseClient, clientId, authorizationCode,
      redirectUrl: redirectUrl);
  // Google API builds us a self-refreshing client from the token+ retrieved
  var authClient = auth.authenticatedClient(baseClient, accessCredentials);
  var peepsApi = peeps.PeopleApi(authClient);
  var userPerson = await peepsApi.people
      .get('people/me', personFields: 'names,emailAddresses');
  appSessions[deviceKey].user = {
    'name': userPerson.names[0].displayName,
    'email': userPerson.emailAddresses[0].value
  };
  */
  // handle app session progress stuff
  /*
  appSessions[deviceKey].credentials = accessCredentials;
  appSessions[deviceKey].authgrantRequest = request;
  await request.response.close();
  if (appSessions[deviceKey].authcompleteQuery != null) {
    await appSessions[deviceKey].authcompleteQuery.response.close();
    print('queryAuthComplete closed (held and resolved by authgrant).');
  }
  appSessions[deviceKey].mutex.release();
  print('token received, user data written');*/
}

void authWaitRequest(HttpRequest request) async {
  var deviceKey = request.uri.queryParameters['device_key'];
  var auth = auths.singleWhere((e) => e.deviceKey == deviceKey);
  await auth.mutex.acquire();
  if (auth.complete) {
    await request.response.close();
    print('authWaitRequest closed (arrived after authgrant).');
  } else {
    auth.authWaitRequest = request;
  }
  auth.mutex.release();
}
