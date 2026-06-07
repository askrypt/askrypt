/// Password generator screen — length slider + character-class toggles, ported
/// from the desktop generator (`core/src/passgen.rs`, UI in `src/main.rs`).
///
/// Optionally returns the generated password to the caller: when opened from
/// the entry editor it pops with the value so it can fill the secret field;
/// from the welcome screen it just offers a Copy button.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../passgen.dart';

class PasswordGeneratorScreen extends StatefulWidget {
  const PasswordGeneratorScreen({super.key, this.returnOnUse = false});

  /// When true, shows a "Use this password" action that pops with the result.
  final bool returnOnUse;

  @override
  State<PasswordGeneratorScreen> createState() =>
      _PasswordGeneratorScreenState();
}

class _PasswordGeneratorScreenState extends State<PasswordGeneratorScreen> {
  final _config = PasswordGenConfig();
  String _password = '';
  String? _error;

  @override
  void initState() {
    super.initState();
    _generate();
  }

  void _generate() {
    try {
      setState(() {
        _password = generatePassword(_config);
        _error = null;
      });
    } on PasswordGenException catch (e) {
      setState(() {
        _password = '';
        _error = e.message;
      });
    }
  }

  Future<void> _copy() async {
    if (_password.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: _password));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Password copied')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Password generator')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Expanded(
                    child: SelectableText(
                      _password.isEmpty ? '—' : _password,
                      style: theme.textTheme.titleMedium
                          ?.copyWith(fontFamily: 'monospace'),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Regenerate',
                    icon: const Icon(Icons.refresh),
                    onPressed: _generate,
                  ),
                  IconButton(
                    tooltip: 'Copy',
                    icon: const Icon(Icons.copy),
                    onPressed: _password.isEmpty ? null : _copy,
                  ),
                ],
              ),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
          ],
          const SizedBox(height: 16),
          Text('Length: ${_config.length}', style: theme.textTheme.labelLarge),
          Slider(
            value: _config.length.toDouble(),
            min: PasswordGenConfig.minLength.toDouble(),
            max: PasswordGenConfig.maxLength.toDouble(),
            divisions:
                PasswordGenConfig.maxLength - PasswordGenConfig.minLength,
            label: '${_config.length}',
            onChanged: (v) => setState(() => _config.setLength(v.round())),
            onChangeEnd: (_) => _generate(),
          ),
          _toggle('Uppercase (A–Z)', _config.useUppercase,
              (v) => _config.useUppercase = v),
          _toggle('Lowercase (a–z)', _config.useLowercase,
              (v) => _config.useLowercase = v),
          _toggle('Numbers (0–9)', _config.useNumbers,
              (v) => _config.useNumbers = v),
          _toggle('Symbols (!@#…)', _config.useSymbols,
              (v) => _config.useSymbols = v),
          const SizedBox(height: 16),
          if (widget.returnOnUse)
            FilledButton.icon(
              onPressed: _password.isEmpty
                  ? null
                  : () => Navigator.of(context).pop(_password),
              icon: const Icon(Icons.check),
              label: const Text('Use this password'),
            ),
        ],
      ),
    );
  }

  Widget _toggle(String label, bool value, ValueChanged<bool> set) {
    return SwitchListTile(
      value: value,
      title: Text(label),
      contentPadding: EdgeInsets.zero,
      onChanged: (v) {
        setState(() => set(v));
        _generate();
      },
    );
  }
}
