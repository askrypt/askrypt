/// The breach lookup (port of `core/src/pwned.rs`) and the warning under a
/// field. A `MockClient` stands in for the API, so nothing leaves the test.
library;

import 'package:askrypt/platform/pwned_client.dart';
import 'package:askrypt/widgets/leak_warning.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _passwordSuffix = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

const _body = '0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n'
    '$_passwordSuffix:9659365\r\n'
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n';

PwnedClient _answering(String body, {int status = 200}) =>
    PwnedClient(MockClient((_) async => http.Response(body, status)));

void main() {
  test('range query splits the known vector like core', () {
    final q = pwnedRangeQuery('password');
    expect(q.prefix, '5BAA6');
    expect(q.suffix, _passwordSuffix);
  });

  test('count in range: hit, case, padding, miss', () {
    expect(pwnedCountInRange(_body, _passwordSuffix), 9659365);
    expect(pwnedCountInRange(_body, _passwordSuffix.toLowerCase()), 9659365);
    expect(pwnedCountInRange(_body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0);
    expect(pwnedCountInRange(_body, '0000000000000000000000000000000000A'), 0);
    expect(pwnedCountInRange('', _passwordSuffix), 0);
  });

  test('only the prefix is sent, with padding asked for', () async {
    late http.Request asked;
    final client = PwnedClient(MockClient((request) async {
      asked = request;
      return http.Response(_body, 200);
    }));
    expect(await client.breachCount('password'), 9659365);
    expect(asked.url.toString(), '${pwnedRangeUrl}5BAA6');
    expect(asked.headers['Add-Padding'], 'true');
  });

  test('a failed lookup throws rather than reading as clean', () async {
    await expectLater(_answering('', status: 503).breachCount('password'),
        throwsA(isA<http.ClientException>()));
  });

  group('warning under the field', () {
    Future<TextEditingController> pump(WidgetTester tester, PwnedClient client,
        {bool enabled = true}) async {
      final controller = TextEditingController();
      final watcher = LeakWatcher(
          controller: controller, client: client, enabled: () => enabled);
      addTearDown(() {
        watcher.dispose();
        controller.dispose();
      });
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: Column(children: [
            TextField(controller: controller),
            LeakWarning(watcher, enabled: enabled),
          ]),
        ),
      ));
      return controller;
    }

    testWidgets('appears for a leaked value and clears on edit',
        (tester) async {
      await pump(tester, _answering(_body));
      await tester.enterText(find.byType(TextField), 'password');
      await tester.pump(leakDebounce + const Duration(milliseconds: 50));
      await tester.pump();
      expect(find.text(LeakWarning.message(9659365)), findsOneWidget);
      expect(find.textContaining('9,659,365'), findsOneWidget);

      await tester.enterText(find.byType(TextField), 'password!');
      await tester.pump();
      expect(find.textContaining('known data'), findsNothing);
      // Let the second lookup run out (its suffix is not in the body).
      await tester.pump(leakDebounce + const Duration(milliseconds: 50));
      await tester.pump();
      expect(find.textContaining('known data'), findsNothing);
    });

    testWidgets('a network error shows nothing', (tester) async {
      await pump(tester, _answering('', status: 500));
      await tester.enterText(find.byType(TextField), 'password');
      await tester.pump(leakDebounce + const Duration(milliseconds: 50));
      await tester.pump();
      expect(find.textContaining('known data'), findsNothing);
    });

    testWidgets('turned off, nothing is looked up', (tester) async {
      var calls = 0;
      final client = PwnedClient(MockClient((_) async {
        calls++;
        return http.Response(_body, 200);
      }));
      await pump(tester, client, enabled: false);
      await tester.enterText(find.byType(TextField), 'password');
      await tester.pump(leakDebounce + const Duration(milliseconds: 50));
      expect(calls, 0);
      expect(find.textContaining('known data'), findsNothing);
    });
  });
}
