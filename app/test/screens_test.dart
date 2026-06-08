/// Widget tests for the Phase 3 screens: the create → add-entry → save flow and
/// the lock action, driven through the real app shell with a fake [VaultIo] so
/// no platform file dialogs are involved.
library;

import 'dart:typed_data';

import 'package:askrypt/app.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:askrypt/platform/vault_io.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

/// Records saved bytes and can hand back a vault to "pick".
class FakeVaultIo implements VaultIo {
  Uint8List? saved;
  PickedVault? toPick;

  @override
  Future<PickedVault?> pickVault() async => toPick;

  @override
  Future<String?> saveVault(Uint8List bytes,
      {String suggestedName = 'vault.askrypt'}) async {
    saved = bytes;
    return '/tmp/$suggestedName';
  }
}

void main() {
  Future<void> pumpApp(WidgetTester tester, FakeVaultIo io) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [vaultIoProvider.overrideWithValue(io)],
        child: const AskryptApp(),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('create → add entry → save round-trips through the UI',
      (tester) async {
    final io = FakeVaultIo();
    await pumpApp(tester, io);

    // Welcome → create.
    expect(find.text('Open vault'), findsOneWidget);
    await tester.tap(find.text('Create new vault'));
    await tester.pumpAndSettle();

    // Fill two question/answer rows (q0, a0, q1, a1).
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'First pet?');
    await tester.enterText(fields.at(1), 'Rex');
    await tester.enterText(fields.at(2), 'Birth city?');
    await tester.enterText(fields.at(3), 'Kazan');
    await tester.tap(find.byIcon(Icons.check));
    await tester.pumpAndSettle();

    // Now unlocked on the entries screen.
    expect(find.text('No entries'), findsOneWidget);

    // Add an entry.
    await tester.tap(find.byIcon(Icons.add));
    await tester.pumpAndSettle();
    final entryFields = find.byType(TextField);
    await tester.enterText(entryFields.at(0), 'GitHub'); // name
    await tester.enterText(entryFields.at(2), 'hunter2'); // secret
    await tester.tap(find.byIcon(Icons.check));
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsOneWidget);

    // Save → fake captures bytes that open with the answers we set. The save
    // re-encrypts on a real background isolate, so let real async complete
    // (widget tests otherwise run in a fake-async zone that never advances it).
    await tester.runAsync(() async {
      await tester.tap(find.byIcon(Icons.save));
      while (io.saved == null) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
    });
    await tester.pumpAndSettle();

    expect(io.saved, isNotNull);
    final file = AskryptFile.fromBytes(io.saved!);
    final qd = file.getQuestionsData('Rex');
    final entries = file.decrypt(qd, const ['Kazan']);
    expect(entries.single.name, 'GitHub');
    expect(entries.single.secret, 'hunter2');
  });

  testWidgets('lock returns to the welcome screen', (tester) async {
    final io = FakeVaultIo();
    await pumpApp(tester, io);

    await tester.tap(find.text('Create new vault'));
    await tester.pumpAndSettle();
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Q1');
    await tester.enterText(fields.at(1), 'a1');
    await tester.enterText(fields.at(2), 'Q2');
    await tester.enterText(fields.at(3), 'a2');
    await tester.tap(find.byIcon(Icons.check));
    await tester.pumpAndSettle();

    expect(find.text('No entries'), findsOneWidget);

    // Lock (no unsaved-changes dialog because nothing was modified).
    await tester.tap(find.byIcon(Icons.lock));
    await tester.pumpAndSettle();

    expect(find.text('Create new vault'), findsOneWidget);
  });
}
