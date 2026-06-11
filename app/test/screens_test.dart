/// Widget tests for the Phase 3 screens: the create → add-entry → save flow and
/// the lock action, driven through the real app shell with a fake [VaultIo] so
/// no platform file dialogs are involved.
library;

import 'dart:typed_data';

import 'package:askrypt/app.dart';
import 'package:askrypt/crypto/secret_entry.dart';
import 'package:askrypt/crypto/vault.dart';
import 'package:askrypt/platform/recent_vault_store.dart';
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

/// In-memory recent-vault cache.
class FakeRecentVaultStore implements RecentVaultStore {
  PickedVault? stored;

  @override
  Future<PickedVault?> load() async => stored;

  @override
  Future<void> remember(Uint8List bytes, String name) async =>
      stored = PickedVault(bytes: bytes, name: name);

  @override
  Future<void> forget() async => stored = null;
}

void main() {
  Future<void> pumpApp(WidgetTester tester, FakeVaultIo io,
      {FakeRecentVaultStore? recent}) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          vaultIoProvider.overrideWithValue(io),
          recentVaultStoreProvider
              .overrideWithValue(recent ?? FakeRecentVaultStore()),
        ],
        child: const AskryptApp(),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('create → add entry → save round-trips through the UI',
      (tester) async {
    final io = FakeVaultIo();
    final recent = FakeRecentVaultStore();
    await pumpApp(tester, io, recent: recent);

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
    // (and the round-trip decrypt below) run the real, awaited PBKDF2, so they
    // must execute inside `tester.runAsync` — widget tests otherwise run in a
    // fake-async zone that never advances the derivation to completion.
    late List<SecretEntry> entries;
    await tester.runAsync(() async {
      await tester.tap(find.byIcon(Icons.save));
      while (io.saved == null) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      final file = AskryptFile.fromBytes(io.saved!);
      final qd = await file.getQuestionsData('Rex');
      entries = await file.decrypt(qd, const ['Kazan']);
    });
    await tester.pumpAndSettle();

    expect(io.saved, isNotNull);
    expect(entries.single.name, 'GitHub');
    expect(entries.single.secret, 'hunter2');

    // A successful save refreshes the recent-vault cache with the same bytes.
    expect(recent.stored, isNotNull);
    expect(recent.stored!.bytes, io.saved);
  });

  testWidgets('welcome offers to reopen the remembered vault', (tester) async {
    final bytes = await tester.runAsync(() async => (await AskryptFile.create(
          questions: ['First pet?', 'Birth city?'],
          answers: ['Rex', 'Kazan'],
          entries: const [],
          iterations: 1000,
        ))
            .toBytes());
    final recent = FakeRecentVaultStore()
      ..stored = PickedVault(bytes: bytes!, name: 'my.askrypt');
    await pumpApp(tester, FakeVaultIo(), recent: recent);

    // The cached vault gets its own button; tapping it goes straight to the
    // unlock screen for that file, no picker involved.
    await tester.tap(find.text('Open my.askrypt'));
    await tester.pumpAndSettle();

    expect(find.text('my.askrypt'), findsOneWidget); // unlock app bar title
    expect(find.text('First pet?'), findsOneWidget); // first question shown
  });

  testWidgets('welcome shows no reopen button when nothing is remembered',
      (tester) async {
    await pumpApp(tester, FakeVaultIo());
    expect(find.byIcon(Icons.history), findsNothing);
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
