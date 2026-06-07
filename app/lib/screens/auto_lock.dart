/// Auto-lock: drops the decrypted session when the app is backgrounded or
/// after a period of inactivity — the mobile counterpart of the desktop
/// inactivity Smart Lock (`src/main.rs`).
///
/// Two triggers, both no-ops unless a vault is actually unlocked:
///   • lifecycle — `paused`/`hidden`/`detached` lock immediately (the app is
///     leaving the foreground, e.g. the task switcher or a phone call);
///   • inactivity — a [Timer] reset on every pointer interaction; firing locks.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../session/vault_session.dart';

/// How long without interaction before the vault auto-locks while in the
/// foreground.
const Duration kInactivityTimeout = Duration(minutes: 3);

class AutoLock extends ConsumerStatefulWidget {
  const AutoLock({super.key, required this.child});

  final Widget child;

  @override
  ConsumerState<AutoLock> createState() => _AutoLockState();
}

class _AutoLockState extends ConsumerState<AutoLock>
    with WidgetsBindingObserver {
  Timer? _idleTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    _idleTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  bool get _isUnlocked =>
      ref.read(vaultSessionProvider) is VaultUnlocked;

  void _lock() {
    _idleTimer?.cancel();
    if (_isUnlocked) {
      ref.read(vaultSessionProvider.notifier).lock();
    }
  }

  void _bumpActivity([_]) {
    _idleTimer?.cancel();
    if (!_isUnlocked) return;
    _idleTimer = Timer(kInactivityTimeout, _lock);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        _lock();
      case AppLifecycleState.resumed:
      case AppLifecycleState.inactive:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    // When the vault locks (manually or via background), drop the idle timer so
    // it can't fire a stray no-op while the app sits on the welcome screen.
    ref.listen(vaultSessionProvider, (_, next) {
      if (next is VaultLocked) _idleTimer?.cancel();
    });
    // Reset the idle timer on any pointer activity anywhere in the app.
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: _bumpActivity,
      onPointerSignal: _bumpActivity,
      child: widget.child,
    );
  }
}
