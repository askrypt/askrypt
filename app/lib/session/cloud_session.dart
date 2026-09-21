/// Askrypt-server sign-in state (Riverpod), the mobile twin of `src/link.rs`.
///
/// The app has no sign-in form. It opens a *device link*, launches the page in
/// the browser, and polls until the server hands over a session token — so no
/// account password is ever typed into the app, and the user can register as
/// part of the same flow.
///
/// Sign-in is started only from the locked side of the app: `AutoLock` locks
/// the vault the moment the app leaves the foreground, so a browser trip while
/// unlocked would drop unsaved work. The unlocked tree only *uses* a session.
///
/// Every poll carries the generation it belongs to; cancelling bumps it, so a
/// late reply to a cancelled sign-in cannot install itself.
library;

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

import '../platform/host_name.dart';
import '../platform/server_client.dart';
import '../platform/server_session_store.dart';

/// How long the app keeps polling before it stops on its own. The link stays
/// valid for an hour; "Open the page again" resumes the same one.
const Duration kSignInPollLimit = Duration(minutes: 15);

/// Opens a URL outside the app. Overridden in tests.
typedef UrlOpener = Future<bool> Function(Uri url);

final urlOpenerProvider = Provider<UrlOpener>(
    (ref) => (url) => launchUrl(url, mode: LaunchMode.externalApplication));

/// HTTP transport for every server request. Overridden in tests.
final httpClientProvider = Provider<http.Client>((ref) {
  final client = http.Client();
  ref.onDispose(client.close);
  return client;
});

/// Saved sign-in + server address. Overridden in tests.
final serverSessionStoreProvider =
    Provider<ServerSessionStore>((ref) => SecureServerSessionStore());

sealed class CloudState {
  const CloudState(this.serverUrl);

  /// The configured server, normalized.
  final String serverUrl;
}

class CloudSignedOut extends CloudState {
  const CloudSignedOut(super.serverUrl, {this.starting = false, this.error});

  /// The request that opens a link is in flight.
  final bool starting;

  /// Why the last attempt ended, for the user.
  final String? error;
}

/// The browser has the sign-in.
class CloudLinking extends CloudState {
  const CloudLinking(super.serverUrl,
      {required this.userCode, required this.url, this.stalled = false});

  /// Shown so the user can compare it with the page — the one thing that makes
  /// approving-on-sight safe.
  final String userCode;
  final String url;

  /// Polling stopped on its own after [kSignInPollLimit].
  final bool stalled;
}

class CloudSignedIn extends CloudState {
  const CloudSignedIn(super.serverUrl,
      {required this.client, required this.email});

  final ServerClient client;
  final String email;

  /// Whether this session can reach the vault stored for [baseUrl]/[email].
  bool serves(String baseUrl, String email) =>
      client.baseUrl == baseUrl && this.email == email;
}

class CloudNotifier extends Notifier<CloudState> {
  int _generation = 0;
  BrowserLogin? _link;
  Timer? _timer;
  DateTime _started = DateTime.now();
  bool _polling = false;

  /// Completes once the saved session (if any) has been read back.
  late Future<void> ready;

  @override
  CloudState build() {
    ref.onDispose(() => _timer?.cancel());
    ready = _restore();
    return const CloudSignedOut(defaultServerUrl);
  }

  ServerSessionStore get _store => ref.read(serverSessionStoreProvider);

  Future<void> _restore() async {
    try {
      final url =
          normalizeBaseUrl(await _store.loadServerUrl() ?? defaultServerUrl);
      final saved = await _store.load();
      if (!ref.mounted) return;
      // The user may have started something while we were reading.
      final now = state;
      if (now is! CloudSignedOut || now.starting) return;
      if (saved != null && normalizeBaseUrl(saved.baseUrl) == url) {
        state = CloudSignedIn(url,
            client: ServerClient(
                baseUrl: url,
                token: saved.token,
                httpClient: ref.read(httpClientProvider)),
            email: saved.email);
      } else {
        state = CloudSignedOut(url);
      }
    } catch (_) {
      // Unreadable storage means "not signed in".
    }
  }

  /// Point the app at another server. Signs out of a different one first,
  /// like desktop: a session belongs to the server that issued it.
  Future<void> setServerUrl(String raw) async {
    final url = normalizeBaseUrl(raw);
    if (url.isEmpty || url == state.serverUrl) return;
    final now = state;
    if (now is CloudLinking) return;
    if (now is CloudSignedIn) await signOut();
    if (!ref.mounted) return;
    state = CloudSignedOut(url);
    try {
      await _store.saveServerUrl(url);
    } catch (_) {}
  }

  /// Begin a sign-in: open a link and launch the browser.
  Future<void> signIn() async {
    final now = state;
    if (now is! CloudSignedOut || now.starting) return;
    final url = now.serverUrl;
    final generation = ++_generation;
    state = CloudSignedOut(url, starting: true);

    final BrowserLogin link;
    try {
      link = await BrowserLogin.start(url,
          deviceLabel: currentHostName(),
          httpClient: ref.read(httpClientProvider));
    } on ServerException catch (e) {
      if (ref.mounted && generation == _generation) {
        state = CloudSignedOut(url, error: e.describe());
      }
      return;
    }
    if (!ref.mounted || generation != _generation) {
      unawaited(link.cancel().catchError((Object _) {}));
      return;
    }

    _link = link;
    _started = DateTime.now();
    state = CloudLinking(url, userCode: link.userCode, url: link.verificationUrl);
    await _openPage(link.verificationUrl);
    _schedule(generation, link.interval);
  }

  /// Launch the browser at the same link again, resuming a stalled wait.
  Future<void> reopen() async {
    final now = state;
    final link = _link;
    if (now is! CloudLinking || link == null) return;
    if (now.stalled) {
      _started = DateTime.now();
      state = CloudLinking(now.serverUrl, userCode: now.userCode, url: now.url);
      _schedule(_generation, link.interval);
    }
    await _openPage(now.url);
  }

  /// Ask right away — the user just came back from the browser.
  void pollNow() {
    final now = state;
    if (now is! CloudLinking || now.stalled) return;
    _timer?.cancel();
    unawaited(_poll(_generation));
  }

  /// Stop waiting, and tell the server so the link stops being approvable.
  void cancel() {
    final link = _link;
    _dropLink();
    state = CloudSignedOut(state.serverUrl);
    if (link != null) unawaited(link.cancel().catchError((Object _) {}));
  }

  /// Revoke the session on the server (best effort) and forget it here.
  Future<void> signOut() async {
    final now = state;
    _dropLink();
    state = CloudSignedOut(now.serverUrl);
    try {
      await _store.clear();
    } catch (_) {}
    if (now is CloudSignedIn) {
      try {
        await now.client.logout();
      } catch (_) {}
    }
  }

  /// The server refused our token (401/403): forget it and say so.
  Future<void> sessionRejected() async {
    _dropLink();
    state = CloudSignedOut(state.serverUrl,
        error: 'Your sign-in is no longer valid. Sign in again.');
    try {
      await _store.clear();
    } catch (_) {}
  }

  void _dropLink() {
    _generation++;
    _timer?.cancel();
    _timer = null;
    _link = null;
  }

  Future<void> _openPage(String url) async {
    try {
      await ref.read(urlOpenerProvider)(Uri.parse(url));
    } catch (_) {
      // The card still shows the code and "Open the page again".
    }
  }

  void _schedule(int generation, Duration after) {
    _timer?.cancel();
    _timer = Timer(after, () => _poll(generation));
  }

  Future<void> _poll(int generation) async {
    final link = _link;
    if (link == null || generation != _generation || _polling) return;
    _polling = true;
    LoginPoll result;
    try {
      result = await link.poll();
    } on ServerException catch (e) {
      _polling = false;
      if (!ref.mounted || generation != _generation) return;
      if (e.isRateLimited || e.kind == ServerErrorKind.network) {
        // Not a failure: the server wants us slower, or the phone is between
        // networks mid-sign-in. Keep waiting.
        _schedule(generation, link.interval);
        return;
      }
      _dropLink();
      state = CloudSignedOut(state.serverUrl, error: e.describe());
      return;
    }
    _polling = false;
    if (!ref.mounted || generation != _generation) return;

    final url = state.serverUrl;
    switch (result) {
      case LoginPending():
        final now = state;
        if (DateTime.now().difference(_started) >= kSignInPollLimit) {
          if (now is CloudLinking) {
            state = CloudLinking(url,
                userCode: now.userCode, url: now.url, stalled: true);
          }
        } else {
          _schedule(generation, link.interval);
        }
      case LoginApproved(:final client, :final email):
        _dropLink();
        state = CloudSignedIn(url, client: client, email: email);
        try {
          await _store.save(ServerSession(
              baseUrl: client.baseUrl, email: email, token: client.token));
        } catch (_) {
          // Signed in for this run; the next start asks again.
        }
      case LoginDenied():
        _dropLink();
        state = CloudSignedOut(url,
            error: 'That sign-in was denied in the browser.');
      case LoginExpired():
        _dropLink();
        state = CloudSignedOut(url,
            error: 'That sign-in request expired. Start a new one.');
    }
  }
}

final cloudProvider =
    NotifierProvider<CloudNotifier, CloudState>(CloudNotifier.new);
