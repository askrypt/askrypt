// Dev tool: write a Dart-created vault to disk so the Rust core can verify it
// opens (Dart -> Rust interop, incl. ZIP container compatibility).
// Run: dart run tool/make_vault.dart <out_path>
import 'dart:io';

import 'package:askrypt/crypto/secret_entry.dart';
import 'package:askrypt/crypto/vault.dart';

Future<void> main(List<String> args) async {
  final out = args.isNotEmpty ? args[0] : '/tmp/dart_vault.askrypt';
  final file = await AskryptFile.create(
    questions: const ['Mother maiden name?', 'First pet?', 'Born city?'],
    answers: const ['Smith', 'Fluffy', 'New York'],
    entries: [
      SecretEntry(
        name: 'FromDart',
        userName: 'dartuser',
        secret: 'dart-secret-пароль',
        url: 'https://dart.test',
        notes: 'created by Dart',
        entryType: 'password',
        tags: const ['x', 'y'],
        created: 1704067200,
        modified: 1704153600,
        hidden: false,
      ),
    ],
    iterations: 1000,
    translit: false,
  );
  File(out).writeAsBytesSync(file.toBytes());
  stdout.writeln('wrote $out');
}
