import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:askrypt/platform/recent_vault_store.dart';
import 'package:flutter_test/flutter_test.dart';

RecentCloud cloud(String id, [String name = 'Main.askrypt']) => RecentCloud(
    baseUrl: 'https://askrypt.example.com',
    email: 'a@example.com',
    id: id,
    name: name);

void main() {
  late Directory root;
  late FileRecentVaultStore store;

  setUp(() async {
    root = await Directory.systemTemp.createTemp('askrypt-recent-test');
    store = FileRecentVaultStore(directory: () async => root);
  });

  tearDown(() async {
    if (await root.exists()) await root.delete(recursive: true);
  });

  Future<List<String>> names() async =>
      [for (final v in await store.load()) v.name];

  Future<int> cachedFiles() async => (await Directory('${root.path}/recent')
          .list()
          .where((f) => f.path.endsWith('.askrypt'))
          .toList())
      .length;

  test('empty until something is remembered', () async {
    expect(await store.load(), isEmpty);
  });

  test('local and cloud vaults coexist, newest first', () async {
    await store.remember(Uint8List.fromList([1, 2]), 'a.askrypt');
    await store.rememberCloud(cloud('id-1'));
    final found = await store.load();
    expect(found.map((v) => v.name), ['Main.askrypt', 'a.askrypt']);
    expect(found[0], isA<RecentCloud>());
    expect((found[1] as RecentLocal).vault.bytes, [1, 2]);
  });

  test('remembering again moves to the front and refreshes', () async {
    await store.remember(Uint8List.fromList([1]), 'a.askrypt');
    await store.remember(Uint8List.fromList([2]), 'b.askrypt');
    await store.rememberCloud(cloud('id-1'));
    await store.remember(Uint8List.fromList([3]), 'a.askrypt');
    await store.rememberCloud(cloud('id-1', 'Renamed.askrypt'));
    final found = await store.load();
    expect(found.map((v) => v.name),
        ['Renamed.askrypt', 'a.askrypt', 'b.askrypt']);
    expect((found[1] as RecentLocal).vault.bytes, [3]);
  });

  test('keeps at most five and deletes evicted bytes', () async {
    for (var i = 0; i < 7; i++) {
      await store.remember(Uint8List.fromList([i]), '$i.askrypt');
    }
    expect(await names(),
        ['6.askrypt', '5.askrypt', '4.askrypt', '3.askrypt', '2.askrypt']);
    expect(await cachedFiles(), maxRecentVaults);
  });

  test('forget drops one vault and its bytes', () async {
    await store.remember(Uint8List.fromList([1]), 'a.askrypt');
    await store.rememberCloud(cloud('id-1'));
    final found = await store.load();
    await store.forget(found[1]);
    expect(await names(), ['Main.askrypt']);
    expect(await cachedFiles(), 0);
    await store.forget(found[0]);
    expect(await store.load(), isEmpty);
  });

  test('a name with separators cannot choose the path', () async {
    await store.remember(Uint8List.fromList([9]), '../../evil.askrypt');
    expect(await names(), ['../../evil.askrypt']);
    expect(await cachedFiles(), 1);
  });

  test('concurrent remembers keep every entry', () async {
    await Future.wait([
      store.remember(Uint8List.fromList([1]), 'a.askrypt'),
      store.rememberCloud(cloud('id-1')),
      store.remember(Uint8List.fromList([2]), 'b.askrypt'),
    ]);
    expect(await names(), hasLength(3));
  });

  test('migrates the single local vault of earlier versions', () async {
    await File('${root.path}/recent.askrypt').writeAsBytes([7, 7]);
    await File('${root.path}/recent.name').writeAsString('old.askrypt');
    final found = await store.load();
    expect(found.single.name, 'old.askrypt');
    expect((found.single as RecentLocal).vault.bytes, [7, 7]);
    expect(await File('${root.path}/recent.askrypt').exists(), isFalse);
    expect(await File('${root.path}/recent.name').exists(), isFalse);
  });

  test('migrates the single cloud vault of earlier versions', () async {
    await File('${root.path}/recent.json')
        .writeAsString(jsonEncode(cloud('id-1').toJson()));
    final found = await store.load();
    expect(found.single, isA<RecentCloud>());
    expect((found.single as RecentCloud).id, 'id-1');
    expect(await File('${root.path}/recent.json').exists(), isFalse);
  });
}
