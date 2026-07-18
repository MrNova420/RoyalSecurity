#define MyAppName "RoyalSecurity"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "RoyalSecurity"
#define MyAppURL "https://royalsecurity.io"
#define MyAppExeName "royalsecurity.exe"
#define ServiceName "RoyalSecurityAgent"

[Setup]
AppId={{B1E53D08-7A4F-4E3C-9B6D-1F2A8C5E7D9A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=..\installer\output
OutputBaseFilename=RoyalSecurity-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoDescription={#MyAppName} Setup
VersionInfoCopyright=Copyright (C) 2025 {#MyAppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\src-tauri\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\intel\*"; DestDir: "{app}\intel"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{commonappdata}\RoyalSecurity\Database"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\RoyalSecurity\Logs"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\RoyalSecurity\Quarantine"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\RoyalSecurity\Backups"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\RoyalSecurity\State"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\RoyalSecurity\Plugins"; Flags: uninsalwaysuninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start with Windows"; GroupDescription: "Startup:"; Flags: checked

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#ServiceName}"; ValueType: string; ValueName: "ImagePath"; ValueData: """{app}\{#MyAppExeName}"" --service"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install-service"; StatusMsg: "Installing RoyalSecurity Agent service..."; Flags: waituntilterminated runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "--start-service"; StatusMsg: "Starting RoyalSecurity Agent..."; Flags: waituntilterminated runhidden postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--stop-service"; Flags: waituntilterminated runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-service"; Flags: waituntilterminated runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\RoyalSecurity"
