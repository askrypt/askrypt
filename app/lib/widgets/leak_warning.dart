/// The warning under the entry editor's Secret field when its value is in a known
/// breach — the mobile port of `src/leak.rs`.
///
/// A [LeakWatcher] follows one [TextEditingController]: a lookup starts
/// [leakDebounce] after the last edit, and its answer is kept only if the text
/// has not changed since (a generation counter, as on desktop). A failed
/// lookup is logged and shows nothing.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import '../platform/pwned_client.dart';

/// Quiet time after the last keystroke before a lookup goes out.
const Duration leakDebounce = Duration(milliseconds: 800);

class LeakWatcher extends ChangeNotifier {
  LeakWatcher({
    required this.controller,
    required this.client,
    required this.enabled,
  }) {
    _text = controller.text;
    controller.addListener(_onControllerChanged);
    recheck();
  }

  final TextEditingController controller;
  final PwnedClient client;

  /// Read on every check, so turning the setting off stops new lookups.
  final bool Function() enabled;

  String _text = '';
  Timer? _timer;
  int _generation = 0;
  bool _disposed = false;

  /// Breaches the current value was found in, or `null` when not known to be
  /// leaked.
  int? get found => _found;
  int? _found;

  void _onControllerChanged() {
    // The listener also fires for cursor moves; only a new text is an edit.
    if (controller.text == _text) return;
    _text = controller.text;
    recheck();
  }

  /// Forget the old verdict and, when enabled and non-empty, look the value
  /// up after a pause.
  void recheck() {
    final generation = ++_generation;
    _timer?.cancel();
    if (_found != null) {
      _found = null;
      notifyListeners();
    }
    final value = controller.text;
    if (!enabled() || value.isEmpty) return;
    _timer = Timer(leakDebounce, () => _lookup(generation, value));
  }

  Future<void> _lookup(int generation, String value) async {
    try {
      final count = await client.breachCount(value);
      if (_disposed || generation != _generation) return;
      _found = count > 0 ? count : null;
      notifyListeners();
    } catch (e) {
      debugPrint('Leak check failed: $e');
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    controller.removeListener(_onControllerChanged);
    super.dispose();
  }
}

/// `⚠️ Found in N known data breaches — choose another.`, or nothing.
class LeakWarning extends StatelessWidget {
  const LeakWarning(this.watcher, {super.key, required this.enabled});

  final LeakWatcher watcher;
  final bool enabled;

  static String message(int count) {
    final noun = count == 1 ? 'breach' : 'breaches';
    return '⚠️ Found in ${_groupThousands(count)} known data $noun — '
        'choose another.';
  }

  static String _groupThousands(int n) {
    final digits = '$n';
    final out = StringBuffer();
    for (var i = 0; i < digits.length; i++) {
      if (i > 0 && (digits.length - i) % 3 == 0) out.write(',');
      out.write(digits[i]);
    }
    return out.toString();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: watcher,
      builder: (context, _) {
        final count = watcher.found;
        if (!enabled || count == null) return const SizedBox.shrink();
        return Padding(
          padding: const EdgeInsets.only(top: 4, left: 12),
          child: Text(
            message(count),
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: Theme.of(context).colorScheme.error),
          ),
        );
      },
    );
  }
}
