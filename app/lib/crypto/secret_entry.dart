/// Vault entry model — mirrors `SecretEntry` in `core/src/types.rs`.
///
/// JSON keys must match the Rust serde names exactly: `user_name` and `type`
/// are non-obvious (the Dart fields are `userName` / `entryType`).
library;

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
  });

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
      };
}
