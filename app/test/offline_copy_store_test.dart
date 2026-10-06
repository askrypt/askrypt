import 'dart:io';
import 'dart:typed_data';

import 'package:askrypt/platform/offline_copy_store.dart';
import 'package:flutter_test/flutter_test.dart';

OfflineLocation server(String email, String id) => OfflineLocation(
    baseUrl: 'https://askrypt.example.com', email: email, id: id);

void main() {
  late Directory root;
  late FileOfflineCopyStore store;

  setUp(() async {
    root = await Directory.systemTemp.createTemp('askrypt-offline-test');
    store = FileOfflineCopyStore(
        directory: () async => Directory('${root.path}/vaults'));
  });

  tearDown(() async {
    if (await root.exists()) await root.delete(recursive: true);
  });

  test('keys tell accounts and vaults apart', () {
    final a = server('a@example.com', 'id-1').key;
    expect(a, isNot(server('b@example.com', 'id-1').key));
    expect(a, isNot(server('a@example.com', 'id-2').key));
    expect(a, server('a@example.com', 'id-1').key);
  });

  test('a hostile id cannot choose the path', () {
    final key = server('a@example.com', '../../evil').key;
    expect(key, hasLength(64));
    expect(RegExp(r'^[0-9a-f]+$').hasMatch(key), isTrue);
  });

  test('a kept copy loads back, is replaced, and can be removed', () async {
    final location = server('a@example.com', 'id-1');
    expect(await store.load(location), isNull);

    await store.keep(
        location, 'Main.askrypt', Uint8List.fromList([1, 2, 3]), 'etag-1');
    var copy = await store.load(location);
    expect(copy, isNotNull);
    expect(copy!.etag, 'etag-1');
    expect(copy.name, 'Main.askrypt');
    expect(copy.bytes, [1, 2, 3]);
    expect(DateTime.tryParse(copy.cachedAt), isNotNull);
    // Another account's vault with the same id is not this copy.
    expect(await store.load(server('b@example.com', 'id-1')), isNull);

    await store.keep(location, 'Main.askrypt', Uint8List.fromList([4]), 'etag-2');
    copy = await store.load(location);
    expect(copy!.etag, 'etag-2');
    expect(copy.bytes, [4]);

    await store.remove(location);
    expect(await store.load(location), isNull);
  });

  test('a missing archive is no copy', () async {
    final location = server('a@example.com', 'id-1');
    await store.keep(location, 'Main.askrypt', Uint8List(1), 'e');
    await File('${root.path}/vaults/${location.key}.askrypt').delete();
    expect(await store.load(location), isNull);
  });

  test('clearAll deletes every copy', () async {
    final a = server('a@example.com', 'id-1');
    final b = server('a@example.com', 'id-2');
    await store.keep(a, 'A', Uint8List(1), 'e');
    await store.keep(b, 'B', Uint8List(1), 'e');
    await store.clearAll();
    expect(await store.load(a), isNull);
    expect(await store.load(b), isNull);
    await store.clearAll(); // Nothing left is not an error.
  });
}
