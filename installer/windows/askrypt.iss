; Inno Setup script for the Askrypt desktop app.
; Build locally:
;   iscc /DMyAppVersion=0.7.0 installer\windows\askrypt.iss
; (defaults to target\x86_64-pc-windows-msvc\release\askrypt.exe; override
; with /DSourceDir=... to package a different build, e.g. win-gnu)
;
; CI passes the release tag's version and builds against the win-msvc
; target — see .github/workflows/release.yml.

#define MyAppName "Askrypt"
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#define MyAppPublisher "Ruslan Absaliamov"
#define MyAppURL "https://github.com/askrypt/askrypt"
#define MyAppExeName "askrypt.exe"
#define MyAppProgId "Askrypt.Vault"
#ifndef SourceDir
  #define SourceDir "..\..\target\x86_64-pc-windows-msvc\release"
#endif

[Setup]
; This AppId is fixed so Inno recognizes an existing install and upgrades it
; in place rather than creating a side-by-side copy. Never change it.
AppId={{DDC6B5CC-F193-4079-92D3-CDC4C0CCC224}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\target\installer
OutputBaseFilename=askrypt-{#MyAppVersion}-setup
SetupIconFile=..\..\static\logo-128.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; The app is a single binary that reads/writes its own config and vault
; files elsewhere (see AppSettings::config_dir); no admin rights needed.
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "associate"; Description: "Associate .askrypt files with {#MyAppName}"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#SourceDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; HKA resolves to HKCU here since PrivilegesRequired=lowest — no admin rights
; needed to register the association.
Root: HKA; Subkey: "Software\Classes\.askrypt"; ValueType: string; ValueName: ""; ValueData: "{#MyAppProgId}"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\{#MyAppProgId}"; ValueType: string; ValueName: ""; ValueData: "Askrypt Vault"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\{#MyAppProgId}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: associate
Root: HKA; Subkey: "Software\Classes\{#MyAppProgId}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: associate

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leaves settings.json / server_session.json in %APPDATA%\askrypt behind on
; uninstall, matching how the app itself never deletes them — vaults and
; settings outlive a reinstall.

[Code]
procedure SHChangeNotify(wEventId, uFlags, dwItem1, dwItem2: Longint);
  external 'SHChangeNotify@shell32.dll stdcall';

const
  SHCNE_ASSOCCHANGED = $8000000;
  SHCNF_IDLIST = $0;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  // Tells Explorer to re-read the file association immediately, rather than
  // waiting for the next logoff/logon, when the task was selected.
  if (CurStep = ssPostInstall) and IsTaskSelected('associate') then
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);
end;
