/// Vault entry model — mirrors `SecretEntry` in `core/src/types.rs`.
///
/// JSON keys must match the Rust serde names exactly: `user_name` and `type`
/// are non-obvious (the Dart fields are `userName` / `entryType`).
///
/// The six `card_*` keys carry meaning only for `type: "Card"` entries. Rust
/// groups them into a `CardFields` struct and flattens it; there is no `card`
/// object on the wire, so they are plain fields here. **This app shows and
/// edits none of them yet** — it carries them so that editing a card entry
/// written by the desktop app cannot silently delete its card. Each is omitted
/// from [toJson] when empty, matching Rust's `skip_serializing_if`, so an entry
/// that is not a card serializes exactly as it did before these existed.
///
/// [Attachment] is carried for exactly the same reason, and it matters more:
/// this app lists attached files and can save one out, but it cannot add or
/// remove one. Were the key dropped on the way back out, a single save here
/// would delete every attachment reference in the vault — and the blobs with
/// them, since [AskryptFile.create] writes only what the entries still refer
/// to.
library;

/// One file attached to an entry — the metadata half. The bytes live in their
/// own `files/<id>` ZIP member, encrypted under the vault's master key; see
/// `SPEC.md`, "File attachments". Mirrors `Attachment` in `core/src/types.rs`.
class Attachment {
  Attachment({
    required this.id,
    required this.name,
    required this.size,
    required this.added,
    required this.iv,
  });

  /// 32 lowercase hex characters, naming the `files/<id>` ZIP member. Random,
  /// so the archive listing never says what the file is called.
  final String id;

  /// The file's real name.
  final String name;

  /// Length of the plaintext in bytes.
  final int size;

  /// When the file was attached, Unix time in seconds.
  final int added;

  /// Base64 of the 16-byte AES-CBC IV this attachment was encrypted under.
  final String iv;

  factory Attachment.fromJson(Map<String, dynamic> json) => Attachment(
        id: json['id'] as String,
        name: json['name'] as String,
        size: (json['size'] as num).toInt(),
        added: (json['added'] as num).toInt(),
        iv: json['iv'] as String,
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'size': size,
        'added': added,
        'iv': iv,
      };
}

class SecretEntry {
  SecretEntry({
    required this.name,
    required this.userName,
    required this.secret,
    required this.url,
    required this.notes,
    required this.entryType,
    required this.tags,
    required this.created,
    required this.modified,
    this.hidden = false,
    this.cardHolder = '',
    this.cardBrand = '',
    this.cardNumber = '',
    this.cardExpiry = '',
    this.cardCvv = '',
    this.cardPin = '',
    List<Attachment>? attachments,
  }) : attachments = attachments ?? <Attachment>[];

  String name;
  String userName;
  String secret;
  String url;
  String notes;
  String entryType;
  List<String> tags;
  int created;
  int modified;
  bool hidden;

  /// Name embossed on the card.
  String cardHolder;

  /// Card network, e.g. `Visa`. Free-form.
  String cardBrand;

  /// Card number as typed, spaces and all. Secret.
  String cardNumber;

  /// Expiry as `MM/YY`. Stored as typed and never parsed.
  String cardExpiry;

  /// Card security code (CVV/CVC). Secret.
  String cardCvv;

  /// Card PIN. Secret.
  String cardPin;

  /// Files attached to this entry. Empty on an entry that has none, and omitted
  /// from [toJson] when it is, so an entry without attachments serializes
  /// exactly as it did before they existed.
  List<Attachment> attachments;

  factory SecretEntry.fromJson(Map<String, dynamic> json) => SecretEntry(
        name: json['name'] as String,
        userName: json['user_name'] as String,
        secret: json['secret'] as String,
        url: json['url'] as String,
        notes: json['notes'] as String,
        entryType: json['type'] as String,
        tags: (json['tags'] as List<dynamic>).cast<String>(),
        created: json['created'] as int,
        modified: json['modified'] as int,
        hidden: (json['hidden'] as bool?) ?? false,
        cardHolder: (json['card_holder'] as String?) ?? '',
        cardBrand: (json['card_brand'] as String?) ?? '',
        cardNumber: (json['card_number'] as String?) ?? '',
        cardExpiry: (json['card_expiry'] as String?) ?? '',
        cardCvv: (json['card_cvv'] as String?) ?? '',
        cardPin: (json['card_pin'] as String?) ?? '',
        attachments: ((json['attachments'] as List<dynamic>?) ?? const [])
            .map((raw) => Attachment.fromJson(raw as Map<String, dynamic>))
            .toList(),
      );

  Map<String, dynamic> toJson() => {
        'name': name,
        'user_name': userName,
        'secret': secret,
        'url': url,
        'notes': notes,
        'type': entryType,
        'tags': tags,
        'created': created,
        'modified': modified,
        'hidden': hidden,
        if (cardHolder.isNotEmpty) 'card_holder': cardHolder,
        if (cardBrand.isNotEmpty) 'card_brand': cardBrand,
        if (cardNumber.isNotEmpty) 'card_number': cardNumber,
        if (cardExpiry.isNotEmpty) 'card_expiry': cardExpiry,
        if (cardCvv.isNotEmpty) 'card_cvv': cardCvv,
        if (cardPin.isNotEmpty) 'card_pin': cardPin,
        if (attachments.isNotEmpty)
          'attachments': attachments.map((a) => a.toJson()).toList(),
      };
}
