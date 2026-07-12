#define MyAppName "Eagle Eye SOC Platform"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Upenyu Hlangabeza"
#define MyAppExeName "EagleEye.exe"

[Setup]
AppId={{F6294980-13A0-4A91-9D25-9E1979CD07AD}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Eagle Eye
DefaultGroupName=Eagle Eye
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=Eagle-Eye-Setup-x64
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "..\dist\EagleEye\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Eagle Eye"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Eagle Eye"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Eagle Eye"; Flags: nowait postinstall skipifsilent
