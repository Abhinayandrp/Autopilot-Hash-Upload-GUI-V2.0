<#
.SYNOPSIS
    Autopilot Device Hash Gather Utility (WPF edition)

.DESCRIPTION
    WPF port of the original WinForms tool. Preserves every piece of business
    logic — WMI device lookup, AES-256 passphrase-encrypted config, browser
    OAuth via HttpListener loopback, automatic app-registration provisioning,
    hardware-hash WMI read, Graph import, and the Autopilot profile poll —
    while moving the UI to DPI-crisp WPF with a light Fluent theme.

    Runs all long operations in a background runspace driven by $syncHash.

.VERSION
    2.0.0

.AUTHOR
    Abhinay Pal

.LASTUPDATED
    2026-04-13
#>

# ─── Script Directory ──────────────────────────────────────────────
function Get-ScriptDirectory {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    if ($HostInvocation -and $HostInvocation.MyCommand.Path) { return (Split-Path -Parent $HostInvocation.MyCommand.Path) }
    if ($env:SCRIPT_DIR) { return $env:SCRIPT_DIR }
    return (Get-Location).Path
}
$ScriptDir = Get-ScriptDirectory

# ─── WPF Assemblies ────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Web

# ─── Logging ───────────────────────────────────────────────────────
$logFolder = "C:\AutopilotLogs"
if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logFolder "AutopilotLog_$timestamp.txt"

# ─── Device Info (WMI) ─────────────────────────────────────────────
$comp         = Get-WmiObject -Class Win32_ComputerSystem
$domain       = $comp.Domain
$deviceName   = $comp.Name
$model        = $comp.Model
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystemProduct).Vendor
if (-not $manufacturer) { $manufacturer = $comp.Manufacturer }
if (-not $manufacturer) { $manufacturer = (Get-WmiObject -Class Win32_BIOS).Manufacturer }
if (-not $manufacturer) { $manufacturer = "<unknown>" }
$serial = (Get-CimInstance win32_bios).SerialNumber

# ─── App Config Path ───────────────────────────────────────────────
$appConfigPath = Join-Path $ScriptDir "AutopilotApp_Config.json"

# ─── Secret protection (AES-256 with PBKDF2 passphrase) ────────────
# Stored format: enc:aes256:v1:<base64 salt>:<base64 iv>:<base64 ciphertext>
# The passphrase is entered once per session via a WPF prompt and cached
# in memory only — never written to disk. PBKDF2-HMAC-SHA1, 200k iterations.
$script:SecretMarker      = "enc:aes256:v1:"
$script:LegacyDpapiMarker = "enc:dpapi:v1:"
$script:SessionPassphrase = $null
$script:SecretCancelled   = $false

function Show-PassphrasePrompt {
    param(
        [string]$Title = "Passphrase Required",
        [string]$Intro,
        [switch]$Create,
        [System.Windows.Window]$Owner
    )

    [xml]$ppXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Title"
        Width="460" SizeToContent="Height"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        ShowInTaskbar="False"
        Topmost="True"
        FontFamily="Segoe UI" FontSize="12">
    <Window.Resources>
        <LinearGradientBrush x:Key="ChromeGradient" StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#F5F3FF" Offset="0"/>
            <GradientStop Color="#EDE9FE" Offset="1"/>
        </LinearGradientBrush>
    </Window.Resources>
    <Window.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#F5F3FF" Offset="0"/>
            <GradientStop Color="#EDE9FE" Offset="1"/>
        </LinearGradientBrush>
    </Window.Background>
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Name="lblIntro" Grid.Row="0" TextWrapping="Wrap" Foreground="#1F2937" Margin="0,0,0,10"/>
        <TextBlock Grid.Row="1" Text="Passphrase:" Foreground="#374151" Margin="0,0,0,4"/>
        <PasswordBox Name="pb1" Grid.Row="2" Height="28" Padding="6,4" BorderBrush="#E5E7EB"/>
        <TextBlock Name="lblConfirm" Grid.Row="3" Text="Confirm passphrase:" Foreground="#374151" Margin="0,10,0,4" Visibility="Collapsed"/>
        <PasswordBox Name="pb2" Grid.Row="4" Height="28" Padding="6,4" BorderBrush="#E5E7EB" Visibility="Collapsed"/>
        <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button Name="btnOk" Content="OK" Width="90" Height="32" Margin="0,0,8,0"
                    Background="#7C3AED" Foreground="White" BorderThickness="0" FontWeight="SemiBold" IsDefault="True"/>
            <Button Name="btnCancel" Content="Cancel" Width="90" Height="32" IsCancel="True"
                    Background="#F3F4F6" Foreground="#1F2937" BorderBrush="#E5E7EB" BorderThickness="1"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $ppReader = New-Object System.Xml.XmlNodeReader $ppXaml
    $ppWindow = [System.Windows.Markup.XamlReader]::Load($ppReader)
    if ($Owner) { $ppWindow.Owner = $Owner }

    $lblIntro   = $ppWindow.FindName('lblIntro')
    $pb1        = $ppWindow.FindName('pb1')
    $pb2        = $ppWindow.FindName('pb2')
    $lblConfirm = $ppWindow.FindName('lblConfirm')
    $btnOk      = $ppWindow.FindName('btnOk')
    $btnCancel  = $ppWindow.FindName('btnCancel')

    $lblIntro.Text = if ($Intro) { $Intro }
                     elseif ($Create) {
                         "Create a passphrase to encrypt the Entra client secret at rest. You will enter this passphrase on every machine that runs this tool."
                     } else {
                         "Enter the passphrase that was used to encrypt the saved credentials."
                     }

    if ($Create) {
        $lblConfirm.Visibility = 'Visible'
        $pb2.Visibility        = 'Visible'
    }

    $script:__ppResult = $null

    $btnOk.Add_Click({
        $pw = $pb1.Password
        if ([string]::IsNullOrEmpty($pw)) {
            [System.Windows.MessageBox]::Show($ppWindow, "Passphrase cannot be empty.", "Error", 'OK', 'Warning') | Out-Null
            return
        }
        if ($Create) {
            if ($pb2.Password -ne $pw) {
                [System.Windows.MessageBox]::Show($ppWindow, "Passphrases do not match.", "Error", 'OK', 'Warning') | Out-Null
                $pb2.Password = ""
                return
            }
            if ($pw.Length -lt 8) {
                [System.Windows.MessageBox]::Show($ppWindow, "Passphrase must be at least 8 characters.", "Error", 'OK', 'Warning') | Out-Null
                return
            }
        }
        $script:__ppResult = $pw
        $ppWindow.DialogResult = $true
        $ppWindow.Close()
    })
    $btnCancel.Add_Click({
        $script:__ppResult = $null
        $ppWindow.DialogResult = $false
        $ppWindow.Close()
    })

    $ppWindow.Add_Loaded({ $pb1.Focus() | Out-Null })
    [void]$ppWindow.ShowDialog()
    return $script:__ppResult
}

function Get-SessionPassphrase {
    param([switch]$Create, [System.Windows.Window]$Owner)
    if ($script:SessionPassphrase) { return $script:SessionPassphrase }
    $pw = Show-PassphrasePrompt -Create:$Create -Owner $Owner
    if (-not $pw) {
        $script:SecretCancelled = $true
        throw [System.OperationCanceledException]::new("PASSPHRASE_CANCELLED")
    }
    $script:SessionPassphrase = $pw
    return $pw
}

function Protect-SecretValue {
    param([string]$Plain, [System.Windows.Window]$Owner)
    if ([string]::IsNullOrEmpty($Plain)) { return "" }
    if ($Plain.StartsWith($script:SecretMarker)) { return $Plain }
    $pw = Get-SessionPassphrase -Create -Owner $Owner

    $salt = New-Object byte[] 16
    $iv   = New-Object byte[] 16
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt); $rng.GetBytes($iv)

    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pw, $salt, 200000)
    $key    = $derive.GetBytes(32)

    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Key     = $key
    $aes.IV      = $iv
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $enc         = $aes.CreateEncryptor()
    $plainBytes  = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    $cipherBytes = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    $enc.Dispose(); $aes.Dispose(); $derive.Dispose()

    return ($script:SecretMarker +
            [Convert]::ToBase64String($salt)   + ":" +
            [Convert]::ToBase64String($iv)     + ":" +
            [Convert]::ToBase64String($cipherBytes))
}

function Unprotect-SecretValue {
    param([string]$Stored, [System.Windows.Window]$Owner)
    if ([string]::IsNullOrEmpty($Stored)) { return "" }
    if ($Stored.StartsWith($script:LegacyDpapiMarker)) {
        try {
            $cipher = $Stored.Substring($script:LegacyDpapiMarker.Length)
            $secure = ConvertTo-SecureString -String $cipher
            $bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        } catch {
            throw "Legacy DPAPI secret could not be decrypted on this machine/user. Delete AutopilotApp_Config.json and re-register the app."
        }
    }
    if (-not $Stored.StartsWith($script:SecretMarker)) { return $Stored }

    $payload = $Stored.Substring($script:SecretMarker.Length)
    $parts   = $payload.Split(':')
    if ($parts.Count -ne 3) { throw "Encrypted secret is corrupt (expected 3 parts)." }
    $salt = [Convert]::FromBase64String($parts[0])
    $iv   = [Convert]::FromBase64String($parts[1])
    $ct   = [Convert]::FromBase64String($parts[2])

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $pw = Get-SessionPassphrase -Owner $Owner
        $derive = $null; $aes = $null; $dec = $null
        try {
            $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pw, $salt, 200000)
            $key    = $derive.GetBytes(32)
            $aes         = [System.Security.Cryptography.Aes]::Create()
            $aes.Key     = $key
            $aes.IV      = $iv
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $dec         = $aes.CreateDecryptor()
            $plainBytes  = $dec.TransformFinalBlock($ct, 0, $ct.Length)
            return [System.Text.Encoding]::UTF8.GetString($plainBytes)
        } catch {
            $script:SessionPassphrase = $null
            if ($attempt -lt 3) {
                $remaining = 3 - $attempt
                [System.Windows.MessageBox]::Show(
                    "Wrong passphrase - decryption failed. $remaining attempt(s) remaining.",
                    "Unlock failed", 'OK', 'Warning') | Out-Null
            }
        } finally {
            if ($dec)    { $dec.Dispose()    }
            if ($aes)    { $aes.Dispose()    }
            if ($derive) { $derive.Dispose() }
        }
    }
    throw "Failed to decrypt saved credentials after 3 attempts."
}

# ─── Shared State ──────────────────────────────────────────────────
$syncHash = [hashtable]::Synchronized(@{
    OutputQueue   = [System.Collections.ArrayList]::new()
    Status        = ""
    Phase         = 0       # 0=idle, 1=prepare, 2=auth, 3=upload, 4=done, -1=error
    Progress      = 0
    IsRunning     = $false
    ErrorOccurred = $false
    Cancelled     = $false
    ScriptDir     = $ScriptDir
    LogFile       = $logFile
    AppConfigPath = $appConfigPath
})

# ─── XAML Definition ───────────────────────────────────────────────
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Autopilot Device Hash Gather"
        Width="920" Height="720" MinWidth="920" MinHeight="720"
        WindowStartupLocation="CenterScreen"
        Foreground="#1F2937"
        FontFamily="Segoe UI" FontSize="12">
    <Window.Resources>
        <LinearGradientBrush x:Key="ChromeGradient" StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#F5F3FF" Offset="0"/>
            <GradientStop Color="#EDE9FE" Offset="1"/>
        </LinearGradientBrush>
        <Style x:Key="AccentButton" TargetType="Button">
            <Setter Property="Background" Value="#7C3AED"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#6D28D9"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="b" Property="Background" Value="#A8AFBA"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="DangerButton" TargetType="Button">
            <Setter Property="Background" Value="#DC2626"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#B91C1C"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="b" Property="Background" Value="#F5B5B5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="#F3F4F6"/>
            <Setter Property="Foreground" Value="#1F2937"/>
            <Setter Property="BorderBrush" Value="#E5E7EB"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#E5E7EB"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="FieldLabel" TargetType="TextBlock">
            <Setter Property="FontSize" Value="10"/>
            <Setter Property="Foreground" Value="#6B7280"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>
        <Style x:Key="FieldValue" TargetType="TextBlock">
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Foreground" Value="#1F2937"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
        </Style>
    </Window.Resources>
    <Window.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#F5F3FF" Offset="0"/>
            <GradientStop Color="#EDE9FE" Offset="1"/>
        </LinearGradientBrush>
    </Window.Background>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="{StaticResource ChromeGradient}" BorderBrush="#E5E7EB" BorderThickness="0,0,0,1" Padding="20,14">
            <StackPanel Orientation="Horizontal">
                <Grid Width="48" Height="48" VerticalAlignment="Center">
                    <Border Name="HeaderLogoPlaceholder" CornerRadius="8" Background="#E5E7EB">
                        <TextBlock Text="LOGO" Foreground="#6B7280" FontSize="11" FontWeight="SemiBold"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <Image Name="HeaderLogo" Stretch="Uniform" Visibility="Collapsed"/>
                </Grid>
                <StackPanel Margin="14,0,0,0" VerticalAlignment="Center">
                    <TextBlock Text="Autopilot Device Hash Gather" FontSize="17" FontWeight="SemiBold" Foreground="#1F2937"/>
                    <TextBlock Text="Register this device with Microsoft Intune Autopilot" FontSize="11" Foreground="#6B7280" Margin="0,2,0,0"/>
                </StackPanel>
            </StackPanel>
        </Border>

        <!-- Tabs -->
        <TabControl Grid.Row="1" Name="tabControl" Background="{StaticResource ChromeGradient}" BorderThickness="0" Padding="0" Margin="0"
                    HorizontalContentAlignment="Stretch" VerticalContentAlignment="Stretch">
            <TabControl.Template>
                <ControlTemplate TargetType="TabControl">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <Border Grid.Row="0" BorderBrush="#D1D5DB" BorderThickness="0,0,0,1">
                            <TabPanel IsItemsHost="True" Panel.ZIndex="1" Margin="0,0,0,-1" Background="Transparent"/>
                        </Border>
                        <Border Grid.Row="1" Background="Transparent">
                            <ContentPresenter ContentSource="SelectedContent"/>
                        </Border>
                    </Grid>
                </ControlTemplate>
            </TabControl.Template>
            <!-- Hash Upload Tab -->
            <TabItem Header="Hash Upload" Name="tabUpload">
                <Grid Margin="20,14,20,14" VerticalAlignment="Stretch" HorizontalAlignment="Stretch">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Device Info Card -->
                    <Border Grid.Row="0" BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="6" Padding="16,12" Background="#FFFFFF">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="6"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="8"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Row="0" Grid.ColumnSpan="3" Text="DEVICE INFORMATION"
                                       FontSize="10" FontWeight="Bold" Foreground="#7C3AED" Margin="0,0,0,8"/>

                            <StackPanel Grid.Row="2" Grid.Column="0">
                                <TextBlock Text="DEVICE NAME" Style="{StaticResource FieldLabel}"/>
                                <TextBlock Name="lblDeviceName" Text="-" Style="{StaticResource FieldValue}"/>
                            </StackPanel>
                            <StackPanel Grid.Row="2" Grid.Column="1">
                                <TextBlock Text="MANUFACTURER" Style="{StaticResource FieldLabel}"/>
                                <TextBlock Name="lblManufacturer" Text="-" Style="{StaticResource FieldValue}"/>
                            </StackPanel>
                            <StackPanel Grid.Row="2" Grid.Column="2">
                                <TextBlock Text="MODEL" Style="{StaticResource FieldLabel}"/>
                                <TextBlock Name="lblModel" Text="-" Style="{StaticResource FieldValue}"/>
                            </StackPanel>

                            <StackPanel Grid.Row="4" Grid.Column="0">
                                <TextBlock Text="DOMAIN" Style="{StaticResource FieldLabel}"/>
                                <TextBlock Name="lblDomain" Text="-" Style="{StaticResource FieldValue}"/>
                            </StackPanel>
                            <StackPanel Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2">
                                <TextBlock Text="SERIAL NUMBER" Style="{StaticResource FieldLabel}"/>
                                <TextBlock Name="lblSerial" Text="-" Style="{StaticResource FieldValue}"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Phase Stepper -->
                    <Grid Grid.Row="1" Margin="0,16,0,6" Height="70">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <StackPanel Grid.Column="0" HorizontalAlignment="Center">
                            <Grid Width="36" Height="36">
                                <Ellipse Name="circle1" Fill="#E5E7EB" Stroke="#E5E7EB" StrokeThickness="1"/>
                                <TextBlock Name="circle1Text" Text="1" Foreground="#6B7280" FontWeight="Bold"
                                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Grid>
                            <TextBlock Name="circle1Label" Text="Prepare" Foreground="#6B7280" FontSize="11"
                                       HorizontalAlignment="Center" Margin="0,6,0,0"/>
                        </StackPanel>
                        <Border Grid.Column="1" Name="conn1" Height="2" Background="#E5E7EB" VerticalAlignment="Center" Margin="8,0,8,18"/>

                        <StackPanel Grid.Column="2" HorizontalAlignment="Center">
                            <Grid Width="36" Height="36">
                                <Ellipse Name="circle2" Fill="#E5E7EB" Stroke="#E5E7EB" StrokeThickness="1"/>
                                <TextBlock Name="circle2Text" Text="2" Foreground="#6B7280" FontWeight="Bold"
                                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Grid>
                            <TextBlock Name="circle2Label" Text="Authenticate" Foreground="#6B7280" FontSize="11"
                                       HorizontalAlignment="Center" Margin="0,6,0,0"/>
                        </StackPanel>
                        <Border Grid.Column="3" Name="conn2" Height="2" Background="#E5E7EB" VerticalAlignment="Center" Margin="8,0,8,18"/>

                        <StackPanel Grid.Column="4" HorizontalAlignment="Center">
                            <Grid Width="36" Height="36">
                                <Ellipse Name="circle3" Fill="#E5E7EB" Stroke="#E5E7EB" StrokeThickness="1"/>
                                <TextBlock Name="circle3Text" Text="3" Foreground="#6B7280" FontWeight="Bold"
                                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Grid>
                            <TextBlock Name="circle3Label" Text="Upload Hash" Foreground="#6B7280" FontSize="11"
                                       HorizontalAlignment="Center" Margin="0,6,0,0"/>
                        </StackPanel>
                        <Border Grid.Column="5" Name="conn3" Height="2" Background="#E5E7EB" VerticalAlignment="Center" Margin="8,0,8,18"/>

                        <StackPanel Grid.Column="6" HorizontalAlignment="Center">
                            <Grid Width="36" Height="36">
                                <Ellipse Name="circle4" Fill="#E5E7EB" Stroke="#E5E7EB" StrokeThickness="1"/>
                                <TextBlock Name="circle4Text" Text="4" Foreground="#6B7280" FontWeight="Bold"
                                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Grid>
                            <TextBlock Name="circle4Label" Text="Complete" Foreground="#6B7280" FontSize="11"
                                       HorizontalAlignment="Center" Margin="0,6,0,0"/>
                        </StackPanel>
                    </Grid>

                    <!-- Activity Log header -->
                    <Grid Grid.Row="2" Margin="0,10,0,6">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Text="ACTIVITY LOG" FontSize="10" FontWeight="Bold" Foreground="#6B7280"/>
                        <TextBlock Grid.Column="1" Name="lblLogIndicator" Text="Idle" FontSize="11" Foreground="#6B7280"/>
                    </Grid>

                    <!-- Console -->
                    <Border Grid.Row="3" BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="4" Background="#F8FAFC">
                        <TextBox Name="txtConsole" IsReadOnly="True" Background="#F8FAFC" Foreground="#1F2937"
                                 BorderThickness="0" FontFamily="Consolas" FontSize="12"
                                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                                 TextWrapping="NoWrap" Padding="10,8" AcceptsReturn="True"/>
                    </Border>

                    <!-- Status line -->
                    <Grid Grid.Row="4" Margin="0,10,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Name="lblStatus" Text="Idle" FontSize="12" Foreground="#6B7280"/>
                        <TextBlock Grid.Column="1" Name="lblDots" Text="" FontSize="14" FontWeight="Bold" Foreground="#7C3AED"/>
                    </Grid>

                    <!-- Progress bar pill -->
                    <Border Grid.Row="5" Height="8" CornerRadius="4" Background="#E5E7EB" Margin="0,8,0,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Name="colProgressFill" Width="0*"/>
                                <ColumnDefinition Name="colProgressRest" Width="100*"/>
                            </Grid.ColumnDefinitions>
                            <Border Grid.Column="0" Name="progressFill" CornerRadius="4" Background="#7C3AED"/>
                        </Grid>
                    </Border>

                    <!-- Buttons -->
                    <Grid Grid.Row="6" Margin="0,14,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Button Grid.Column="0" Name="btnStart" Content="Start Autopilot Collection"
                                Style="{StaticResource AccentButton}" Height="40" Margin="0,0,8,0"/>
                        <Button Grid.Column="1" Name="btnAbort" Content="Abort"
                                Style="{StaticResource DangerButton}" Height="40" Width="140" IsEnabled="False" Margin="0,0,8,0"/>
                        <Button Grid.Column="2" Name="btnClose" Content="Close"
                                Style="{StaticResource SecondaryButton}" Height="40" Width="120"/>
                    </Grid>
                </Grid>
            </TabItem>

            <!-- Settings Tab -->
            <TabItem Header="Settings" Name="tabSettings">
                <Grid Margin="24,20,24,20" VerticalAlignment="Stretch" HorizontalAlignment="Stretch">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <TextBlock Grid.Row="0" Text="Configuration" FontSize="18" FontWeight="SemiBold" Foreground="#1F2937"/>
                    <TextBlock Grid.Row="1" Text="Authentication is handled automatically via browser login. No client secrets needed."
                               FontSize="11" Foreground="#6B7280" Margin="0,4,0,16"/>

                    <Grid Grid.Row="2" Margin="0,0,0,12">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="130"/>
                            <ColumnDefinition Width="400"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Text="Tenant ID" FontWeight="SemiBold" Foreground="#374151" VerticalAlignment="Center"/>
                        <TextBox Grid.Column="1" Name="txtTenant" Height="28" Padding="8,4" BorderBrush="#E5E7EB"
                                 FontSize="12" VerticalContentAlignment="Center"/>
                    </Grid>

                    <Grid Grid.Row="3" Margin="0,0,0,16">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="130"/>
                            <ColumnDefinition Width="400"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Text="Group Tag" FontWeight="SemiBold" Foreground="#374151" VerticalAlignment="Center"/>
                        <TextBox Grid.Column="1" Name="txtGroupTag" Height="28" Padding="8,4" BorderBrush="#E5E7EB"
                                 FontSize="12" VerticalContentAlignment="Center"/>
                    </Grid>

                    <StackPanel Grid.Row="4" Orientation="Horizontal">
                        <Button Name="btnSaveSettings" Content="Save Settings"
                                Style="{StaticResource AccentButton}" Height="36" Width="180" Margin="130,0,10,0"/>
                        <Button Name="btnResetApp" Content="Reset App Registration"
                                Style="{StaticResource SecondaryButton}" Height="36" Width="220"/>
                    </StackPanel>

                    <Border Grid.Row="5" Background="#EFF6FF" BorderBrush="#BFDBFE" BorderThickness="1" CornerRadius="6"
                            Padding="14,10" Margin="130,24,0,0" HorizontalAlignment="Left" Width="520">
                        <StackPanel>
                            <TextBlock Text="Authentication: Interactive Browser Login" FontWeight="SemiBold" Foreground="#1E40AF"/>
                            <TextBlock TextWrapping="Wrap" Foreground="#1E40AF" FontSize="11" Margin="0,6,0,0">
                                On first run, an App Registration is created automatically in your tenant
                                (requires Global Admin or Application Admin role). Credentials are saved
                                locally for future runs. Use 'Reset App Registration' to start fresh.
                            </TextBlock>
                        </StackPanel>
                    </Border>
                </Grid>
            </TabItem>

            <!-- About Tab -->
            <TabItem Header="About" Name="tabAbout">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"
                              VerticalAlignment="Stretch" HorizontalAlignment="Stretch">
                    <Border BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="8"
                            Background="#FFFFFF" Padding="24" Margin="24"
                            MaxWidth="720" HorizontalAlignment="Center" VerticalAlignment="Top">
                        <StackPanel>
                            <!-- Header row: title + version pill -->
                            <StackPanel Orientation="Horizontal" HorizontalAlignment="Left">
                                <TextBlock Text="Autopilot Device Hash Gather" FontSize="24" FontWeight="SemiBold" Foreground="#1F2937" VerticalAlignment="Center"/>
                                <Border CornerRadius="10" Background="#7C3AED" Padding="8,2" Margin="10,4,0,0" VerticalAlignment="Center">
                                    <TextBlock Text="v2.0.0" FontSize="11" FontWeight="SemiBold" Foreground="White"/>
                                </Border>
                            </StackPanel>

                            <TextBlock Text="Standalone Autopilot registration utility. No modules. No portal. Just the hash."
                                       FontSize="12" Foreground="#6B7280" Margin="0,8,0,18" TextWrapping="Wrap"/>

                            <!-- Details grid -->
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="170"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>

                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Release Date" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="0" Grid.Column="1" Text="2026-04-13" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                                <Border Grid.Row="1" Grid.ColumnSpan="2" Height="1" Background="#E5E7EB"/>

                                <TextBlock Grid.Row="2" Grid.Column="0" Text="Developer" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="2" Grid.Column="1" Text="Abhinay Pal" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                                <Border Grid.Row="3" Grid.ColumnSpan="2" Height="1" Background="#E5E7EB"/>

                                <TextBlock Grid.Row="4" Grid.Column="0" Text="Platform" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="4" Grid.Column="1" Text="Windows 10 1809+ / Windows 11 (x64 or ARM64)" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                                <Border Grid.Row="5" Grid.ColumnSpan="2" Height="1" Background="#E5E7EB"/>

                                <TextBlock Grid.Row="6" Grid.Column="0" Text="Runtime" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="6" Grid.Column="1" Text="PowerShell 5.1 (no PS7 required)" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                                <Border Grid.Row="7" Grid.ColumnSpan="2" Height="1" Background="#E5E7EB"/>

                                <TextBlock Grid.Row="8" Grid.Column="0" Text="Auth" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="8" Grid.Column="1" Text="Microsoft Graph REST (auto-provisioned app registration)" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                                <Border Grid.Row="9" Grid.ColumnSpan="2" Height="1" Background="#E5E7EB"/>

                                <TextBlock Grid.Row="10" Grid.Column="0" Text="Secret Storage" FontWeight="SemiBold" Foreground="#6B7280" Padding="0,8,12,8"/>
                                <TextBlock Grid.Row="10" Grid.Column="1" Text="AES-256-CBC with PBKDF2-SHA1 (200,000 iterations)" Foreground="#1F2937" Padding="0,8" TextWrapping="Wrap"/>
                            </Grid>

                            <!-- What's new -->
                            <TextBlock Text="What's new in v2.0" FontSize="13" FontWeight="SemiBold" Foreground="#7C3AED" Margin="0,20,0,8"/>
                            <StackPanel>
                                <TextBlock Foreground="#1F2937" Margin="0,2" TextWrapping="Wrap" Text="&#8226;  Standalone &#8212; no AzureAD or WindowsAutoPilotIntune modules"/>
                                <TextBlock Foreground="#1F2937" Margin="0,2" TextWrapping="Wrap" Text="&#8226;  Real-time deployment-profile tracking"/>
                                <TextBlock Foreground="#1F2937" Margin="0,2" TextWrapping="Wrap" Text="&#8226;  Portable AES-256 encrypted config (works on any Windows machine with the passphrase)"/>
                                <TextBlock Foreground="#1F2937" Margin="0,2" TextWrapping="Wrap" Text="&#8226;  Fluent light-theme UI, resizable, DPI-crisp (WPF)"/>
                                <TextBlock Foreground="#1F2937" Margin="0,2" TextWrapping="Wrap" Text="&#8226;  Auto-provisioned Entra app registration"/>
                            </StackPanel>

                            <TextBlock Text="&#169; 2026 Abhinay Pal" FontSize="10" Foreground="#6B7280"
                                       HorizontalAlignment="Center" Margin="0,22,0,0"/>
                        </StackPanel>
                    </Border>
                </ScrollViewer>
            </TabItem>
        </TabControl>
    </Grid>
</Window>
"@

# ─── Load XAML ─────────────────────────────────────────────────────
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Map named elements
$lblDeviceName   = $window.FindName('lblDeviceName')
$lblManufacturer = $window.FindName('lblManufacturer')
$lblModel        = $window.FindName('lblModel')
$lblDomain       = $window.FindName('lblDomain')
$lblSerial       = $window.FindName('lblSerial')

$txtConsole      = $window.FindName('txtConsole')
$lblLogIndicator = $window.FindName('lblLogIndicator')
$lblStatus       = $window.FindName('lblStatus')
$lblDots         = $window.FindName('lblDots')
$progressFill    = $window.FindName('progressFill')
$colProgressFill = $window.FindName('colProgressFill')
$colProgressRest = $window.FindName('colProgressRest')

$btnStart  = $window.FindName('btnStart')
$btnAbort  = $window.FindName('btnAbort')
$btnClose  = $window.FindName('btnClose')

$txtTenant       = $window.FindName('txtTenant')
$txtGroupTag     = $window.FindName('txtGroupTag')
$btnSaveSettings = $window.FindName('btnSaveSettings')
$btnResetApp     = $window.FindName('btnResetApp')
$tabControl      = $window.FindName('tabControl')
$tabSettings     = $window.FindName('tabSettings')

$phaseCircles = @(
    $window.FindName('circle1'),
    $window.FindName('circle2'),
    $window.FindName('circle3'),
    $window.FindName('circle4')
)
$phaseTexts = @(
    $window.FindName('circle1Text'),
    $window.FindName('circle2Text'),
    $window.FindName('circle3Text'),
    $window.FindName('circle4Text')
)
$phaseLabels = @(
    $window.FindName('circle1Label'),
    $window.FindName('circle2Label'),
    $window.FindName('circle3Label'),
    $window.FindName('circle4Label')
)
$phaseConnectors = @(
    $window.FindName('conn1'),
    $window.FindName('conn2'),
    $window.FindName('conn3')
)

# Populate device info
$lblDeviceName.Text   = if ($deviceName)   { $deviceName }   else { "-" }
$lblManufacturer.Text = if ($manufacturer) { $manufacturer } else { "-" }
$lblModel.Text        = if ($model)        { $model }        else { "-" }
$lblDomain.Text       = if ($domain)       { $domain }       else { "-" }
$lblSerial.Text       = if ($serial)       { $serial }       else { "-" }

# ─── Header logo: load logo.png next to script if present ─────────
$HeaderLogo            = $window.FindName('HeaderLogo')
$HeaderLogoPlaceholder = $window.FindName('HeaderLogoPlaceholder')
try {
    $logoPath = Join-Path $ScriptDir 'logo.png'
    if (Test-Path $logoPath) {
        $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $bmp.BeginInit()
        $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bmp.UriSource = New-Object System.Uri -ArgumentList @((Resolve-Path $logoPath).Path)
        $bmp.EndInit()
        $bmp.Freeze()
        $HeaderLogo.Source = $bmp
        $HeaderLogo.Visibility = [System.Windows.Visibility]::Visible
        $HeaderLogoPlaceholder.Visibility = [System.Windows.Visibility]::Collapsed
    }
} catch {
    # Silent fallback to placeholder
}

# ─── Brushes for state changes ─────────────────────────────────────
$brushAccent  = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#7C3AED')
$brushSuccess = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#16A34A')
$brushDanger  = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#DC2626')
$brushMuted   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#6B7280')
$brushPending = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#E5E7EB')
$brushWhite   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FFFFFF')
$brushBorder  = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#E5E7EB')

# ─── Phase glow effects ───────────────────────────────────────────
$phaseGlowColorAccent  = [System.Windows.Media.ColorConverter]::ConvertFromString('#7C3AED')
$phaseGlowColorSuccess = [System.Windows.Media.ColorConverter]::ConvertFromString('#16A34A')
$phaseGlowColorDanger  = [System.Windows.Media.ColorConverter]::ConvertFromString('#DC2626')
$phaseGlowStoryboards  = @($null, $null, $null, $null)

function Clear-PhaseGlow {
    param([int]$Index)
    if ($phaseGlowStoryboards[$Index]) {
        try { $phaseGlowStoryboards[$Index].Stop($phaseCircles[$Index]) } catch {}
        $phaseGlowStoryboards[$Index] = $null
    }
    $phaseCircles[$Index].Effect = $null
}

function Apply-PhaseGlowStatic {
    param([int]$Index, $Color, [double]$BlurRadius = 14, [double]$Opacity = 0.6)
    Clear-PhaseGlow -Index $Index
    $fx = New-Object System.Windows.Media.Effects.DropShadowEffect
    $fx.Color = $Color
    $fx.ShadowDepth = 0
    $fx.BlurRadius = $BlurRadius
    $fx.Opacity = $Opacity
    $phaseCircles[$Index].Effect = $fx
}

function Apply-PhaseGlowPulsing {
    param([int]$Index, $Color)
    Clear-PhaseGlow -Index $Index
    $fx = New-Object System.Windows.Media.Effects.DropShadowEffect
    $fx.Color = $Color
    $fx.ShadowDepth = 0
    $fx.BlurRadius = 12
    $fx.Opacity = 0.8
    $phaseCircles[$Index].Effect = $fx

    $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $anim.From = 12
    $anim.To   = 24
    $anim.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(1200))
    $anim.AutoReverse = $true
    $anim.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever

    $sb = New-Object System.Windows.Media.Animation.Storyboard
    [System.Windows.Media.Animation.Storyboard]::SetTarget($anim, $phaseCircles[$Index])
    $path = New-Object System.Windows.PropertyPath("(UIElement.Effect).(DropShadowEffect.BlurRadius)")
    [System.Windows.Media.Animation.Storyboard]::SetTargetProperty($anim, $path)
    $sb.Children.Add($anim)
    $sb.Begin($phaseCircles[$Index], $true)
    $phaseGlowStoryboards[$Index] = $sb
}

# ─── Phase stepper update helper ───────────────────────────────────
function Set-PhaseState {
    $currentPhase = $syncHash.Phase
    for ($i = 0; $i -lt $phaseCircles.Count; $i++) {
        $tp = $i + 1
        $state = if ($syncHash.ErrorOccurred -and $tp -eq $currentPhase) { "error" }
                 elseif ($tp -lt $currentPhase) { "done" }
                 elseif ($tp -eq $currentPhase -and $syncHash.IsRunning) { "active" }
                 elseif ($tp -eq $currentPhase -and -not $syncHash.IsRunning -and -not $syncHash.ErrorOccurred) { "done" }
                 else { "pending" }

        switch ($state) {
            "active" {
                $phaseCircles[$i].Fill = $brushAccent
                $phaseCircles[$i].Stroke = $brushAccent
                $phaseTexts[$i].Text = ($i + 1).ToString()
                $phaseTexts[$i].Foreground = $brushWhite
                $phaseLabels[$i].Foreground = $brushAccent
                $phaseLabels[$i].FontWeight = [System.Windows.FontWeights]::SemiBold
                Apply-PhaseGlowPulsing -Index $i -Color $phaseGlowColorAccent
            }
            "done" {
                $phaseCircles[$i].Fill = $brushSuccess
                $phaseCircles[$i].Stroke = $brushSuccess
                $phaseTexts[$i].Text = [string][char]0x2713
                $phaseTexts[$i].Foreground = $brushWhite
                $phaseLabels[$i].Foreground = $brushSuccess
                $phaseLabels[$i].FontWeight = [System.Windows.FontWeights]::Normal
                Apply-PhaseGlowStatic -Index $i -Color $phaseGlowColorSuccess -BlurRadius 14 -Opacity 0.6
            }
            "error" {
                $phaseCircles[$i].Fill = $brushDanger
                $phaseCircles[$i].Stroke = $brushDanger
                $phaseTexts[$i].Text = "!"
                $phaseTexts[$i].Foreground = $brushWhite
                $phaseLabels[$i].Foreground = $brushDanger
                $phaseLabels[$i].FontWeight = [System.Windows.FontWeights]::SemiBold
                Apply-PhaseGlowStatic -Index $i -Color $phaseGlowColorDanger -BlurRadius 14 -Opacity 0.6
            }
            default {
                $phaseCircles[$i].Fill = $brushPending
                $phaseCircles[$i].Stroke = $brushPending
                $phaseTexts[$i].Text = ($i + 1).ToString()
                $phaseTexts[$i].Foreground = $brushMuted
                $phaseLabels[$i].Foreground = $brushMuted
                $phaseLabels[$i].FontWeight = [System.Windows.FontWeights]::Normal
                Clear-PhaseGlow -Index $i
            }
        }

        if ($i -lt $phaseConnectors.Count) {
            $phaseConnectors[$i].Background = if ($tp -lt $currentPhase) { $brushSuccess } else { $brushBorder }
        }
    }
}

# ─── Progress bar update (star columns = resize-safe fill) ─────────
function Set-ProgressValue {
    param([double]$Value)
    $v = [math]::Max(0, [math]::Min(100, $Value))
    $colProgressFill.Width = New-Object System.Windows.GridLength($v, [System.Windows.GridUnitType]::Star)
    $colProgressRest.Width = New-Object System.Windows.GridLength((100 - $v), [System.Windows.GridUnitType]::Star)
    if ($syncHash.ErrorOccurred) {
        $progressFill.Background = $brushDanger
    } elseif ($v -ge 100) {
        $progressFill.Background = $brushSuccess
    } else {
        $progressFill.Background = $brushAccent
    }
}

# ─── Load settings fields from JSON ────────────────────────────────
function Load-IniFields {
    if (Test-Path $appConfigPath) {
        try {
            $json = Get-Content $appConfigPath -Raw | ConvertFrom-Json
            $txtTenant.Text   = if ($json.TenantID) { $json.TenantID } else { "" }
            $txtGroupTag.Text = if ($json.GroupTag) { $json.GroupTag } else { "" }
        } catch {
            $txtTenant.Text = ""; $txtGroupTag.Text = ""
        }
    } else {
        $txtTenant.Text = ""; $txtGroupTag.Text = ""
    }
}
Load-IniFields

$tabControl.Add_SelectionChanged({
    if ($tabControl.SelectedItem -eq $tabSettings) { Load-IniFields }
})

$btnSaveSettings.Add_Click({
    $jsonConfig = @{}
    if (Test-Path $appConfigPath) {
        try {
            $existing = Get-Content $appConfigPath -Raw | ConvertFrom-Json
            foreach ($prop in $existing.PSObject.Properties) {
                $jsonConfig[$prop.Name] = $prop.Value
            }
        } catch {}
    }
    $jsonConfig["TenantID"] = $txtTenant.Text
    $jsonConfig["GroupTag"] = $txtGroupTag.Text
    $jsonConfig | ConvertTo-Json | Out-File $appConfigPath -Encoding utf8
    [System.Windows.MessageBox]::Show($window, "Settings saved!", "Success", 'OK', 'Information') | Out-Null
})

$btnResetApp.Add_Click({
    $result = [System.Windows.MessageBox]::Show($window,
        "This will delete the saved app credentials. On next upload, a new app registration will be created and you'll need to sign in again.`n`nContinue?",
        "Reset App Registration", 'YesNo', 'Warning')
    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        $p = Join-Path $ScriptDir "AutopilotApp_Config.json"
        if (Test-Path $p) { Remove-Item $p -Force }
        [System.Windows.MessageBox]::Show($window, "App registration config removed. A new one will be created on next upload.", "Done", 'OK', 'Information') | Out-Null
    }
})

$btnClose.Add_Click({
    # If a background run is active, signal cancellation first so the runspace
    # cleans up cleanly, then close the window. FormClosing cleanup handler
    # will dispose the runspace/timer.
    try {
        if ($syncHash) { $syncHash.Cancelled = $true }
    } catch {}
    $window.Close()
})

# ─── Animation / poll timer (DispatcherTimer, ~20fps) ──────────────
$script:dotCount = 0
$script:animFrame = 0
$script:progressValue = 0.0

$animTimer = New-Object System.Windows.Threading.DispatcherTimer
$animTimer.Interval = [TimeSpan]::FromMilliseconds(50)
$animTimer.Add_Tick({
    $script:animFrame++

    # Drain output queue
    if ($syncHash.OutputQueue.Count -gt 0) {
        $batch = ""
        while ($syncHash.OutputQueue.Count -gt 0) {
            $msg = $syncHash.OutputQueue[0]
            $syncHash.OutputQueue.RemoveAt(0)
            $batch += "$msg`r`n"
        }
        $txtConsole.AppendText($batch)
        $txtConsole.ScrollToEnd()
    }

    # Status text
    if ($syncHash.Status -and $lblStatus.Text -ne $syncHash.Status) {
        $lblStatus.Text = $syncHash.Status
    }

    # Smooth progress animation — cubic ease-out
    $target = [double]$syncHash.Progress
    if ($script:progressValue -lt $target) {
        $delta = $target - $script:progressValue
        $step = [math]::Max(0.35, $delta * 0.14)
        $script:progressValue = [math]::Min($target, $script:progressValue + $step)
        Set-ProgressValue -Value $script:progressValue
    } elseif ($script:progressValue -gt $target) {
        $script:progressValue = $target
        Set-ProgressValue -Value $script:progressValue
    }

    # Dots
    if ($syncHash.IsRunning -and ($script:animFrame % 10 -eq 0)) {
        $script:dotCount = ($script:dotCount % 3) + 1
        $lblDots.Text = "." * $script:dotCount
    }

    # Log indicator
    if ($syncHash.IsRunning -and $lblLogIndicator.Text -ne "Running") {
        $lblLogIndicator.Text = "Running"
        $lblLogIndicator.Foreground = $brushAccent
    }

    # Phase indicators
    if ($syncHash.Phase -gt 0) { Set-PhaseState }

    # Status color
    if ($syncHash.IsRunning) { $lblStatus.Foreground = $brushAccent }

    # Completion
    if (-not $syncHash.IsRunning -and $syncHash.Phase -gt 0 -and $btnStart.Content -eq "Running...") {
        $script:progressValue = 100
        Set-ProgressValue -Value 100

        $lblStatus.Foreground = if ($syncHash.ErrorOccurred) { $brushDanger } else { $brushSuccess }
        $lblDots.Text = ""
        $lblLogIndicator.Text = if ($syncHash.ErrorOccurred) { "Error" } else { "Complete" }
        $lblLogIndicator.Foreground = if ($syncHash.ErrorOccurred) { $brushDanger } else { $brushSuccess }

        $btnStart.IsEnabled = $true
        $btnStart.Content = if ($syncHash.ErrorOccurred) { "Retry Autopilot Collection" } else { "Completed Successfully" }
        $btnAbort.IsEnabled = $false
        Set-PhaseState
    }
})

# ─── Background runspace reference ─────────────────────────────────
$script:bgPowerShell = $null
$script:bgRunspace   = $null

# ─── Abort handler ─────────────────────────────────────────────────
$btnAbort.Add_Click({
    $syncHash.Cancelled = $true
    $syncHash.OutputQueue.Add("[$(Get-Date -Format 'HH:mm:ss')] [ABORT] User requested abort...") | Out-Null

    if ($script:bgPowerShell) {
        try { $script:bgPowerShell.Stop()    } catch {}
        try { $script:bgPowerShell.Dispose() } catch {}
    }
    if ($script:bgRunspace) {
        try { $script:bgRunspace.Close()   } catch {}
        try { $script:bgRunspace.Dispose() } catch {}
    }

    $syncHash.IsRunning = $false
    $syncHash.ErrorOccurred = $true
    $syncHash.Status = "Aborted by user."
    $syncHash.Progress = 100

    $btnStart.IsEnabled = $true
    $btnStart.Content = "Start Autopilot Collection"
    $btnAbort.IsEnabled = $false
    $lblLogIndicator.Text = "Aborted"
    $lblLogIndicator.Foreground = $brushDanger
})

# ─── Start button ──────────────────────────────────────────────────
$btnStart.Add_Click({
  try {
    $script:SecretCancelled = $false
    # Disable UI
    $btnStart.IsEnabled = $false
    $btnStart.Content = "Running..."
    $btnAbort.IsEnabled = $true
    $txtConsole.Clear()

    # Reset state
    $script:progressValue = 0.0
    $script:dotCount = 0
    $syncHash.OutputQueue.Clear()
    $syncHash.Status = "Initializing..."
    $syncHash.Phase = 0
    $syncHash.Progress = 2
    $syncHash.IsRunning = $true
    $syncHash.ErrorOccurred = $false
    $syncHash.Cancelled = $false

    # Reset phase visuals
    for ($i = 0; $i -lt $phaseCircles.Count; $i++) {
        $phaseCircles[$i].Fill = $brushPending
        $phaseCircles[$i].Stroke = $brushPending
        $phaseTexts[$i].Text = ($i + 1).ToString()
        $phaseTexts[$i].Foreground = $brushMuted
        $phaseLabels[$i].Foreground = $brushMuted
        $phaseLabels[$i].FontWeight = [System.Windows.FontWeights]::Normal
    }
    foreach ($c in $phaseConnectors) { $c.Background = $brushBorder }
    Set-ProgressValue -Value 0

    $lblStatus.Foreground = $brushAccent
    $lblLogIndicator.Text = "Running"
    $lblLogIndicator.Foreground = $brushAccent

    $animTimer.Start()

    function Write-UILog {
        param([string]$text)
        $line = "[$(Get-Date -Format 'HH:mm:ss')] $text"
        $syncHash.OutputQueue.Add($line) | Out-Null
        Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
    }

    # Helper to pump the WPF dispatcher while we block on I/O
    $pumpDispatcher = {
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
            [System.Windows.Threading.DispatcherPriority]::Background,
            [Action]{ $frame.Continue = $false }) | Out-Null
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    }

    # ═══════════════════════════════════════════════════════
    # PHASE 1: Prepare
    # ═══════════════════════════════════════════════════════
    $syncHash.Phase = 1
    $syncHash.Status = "Preparing..."
    $syncHash.Progress = 10
    Write-UILog "[Prepare] Starting..."

    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem
        Write-UILog "[Prepare] OS: $($osInfo.Caption) ($($osInfo.Version))"
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { throw "Administrator privileges required to read the device hardware hash." }
        Write-UILog "[Prepare] Administrator: yes"

        try {
            $null = [System.Net.Dns]::GetHostEntry("graph.microsoft.com")
            Write-UILog "[Prepare] Internet connectivity: OK"
        } catch {
            throw "Cannot reach graph.microsoft.com - check your internet connection."
        }

        $syncHash.Progress = 25
        Write-UILog "[Prepare] Ready."
    } catch {
        Write-UILog "[ERROR] $($_.Exception.Message)"
        $syncHash.ErrorOccurred = $true
        $syncHash.Status = "Failed: $($_.Exception.Message)"
        $syncHash.Progress = 100
        $syncHash.IsRunning = $false
        $btnStart.IsEnabled = $true
        $btnStart.Content = "Start Autopilot Collection"
        $btnAbort.IsEnabled = $false
        return
    }

    # ═══════════════════════════════════════════════════════
    # PHASE 2: Authenticate (UI thread — needs browser popup)
    # ═══════════════════════════════════════════════════════
    $syncHash.Phase = 2
    $syncHash.Status = "Setting up authentication..."
    $syncHash.Progress = 38

    $script:grouptag = ""
    $script:uploadTenantId = ""

    if (Test-Path $appConfigPath) {
        try {
            $savedCfg = Get-Content $appConfigPath -Raw | ConvertFrom-Json
            $script:grouptag       = if ($savedCfg.GroupTag) { $savedCfg.GroupTag } else { "" }
            $script:uploadTenantId = if ($savedCfg.TenantID) { $savedCfg.TenantID } else { "" }
        } catch {}
    }

    # Prefer live textbox values over saved JSON
    $liveTag = $txtGroupTag.Text
    if (-not [string]::IsNullOrWhiteSpace($liveTag))    { $script:grouptag = $liveTag.Trim() }
    $liveTenant = $txtTenant.Text
    if (-not [string]::IsNullOrWhiteSpace($liveTenant)) { $script:uploadTenantId = $liveTenant.Trim() }

    if ($script:grouptag) { Write-UILog "[Authenticate] Group Tag: $($script:grouptag)" }
    else                  { Write-UILog "[Authenticate] No Group Tag set (device uploaded without tag)" }

    $script:appConfig = $null
    $needsNewApp = $true

    if (Test-Path $appConfigPath) {
        try {
            $script:appConfig = Get-Content $appConfigPath -Raw | ConvertFrom-Json
            if ($script:appConfig.ClientID -and $script:appConfig.ClientSecret) {
                $storedSecret = [string]$script:appConfig.ClientSecret
                if (-not $storedSecret.StartsWith($script:SecretMarker)) {
                    Write-UILog "[Authenticate] Upgrading stored secret to portable AES-256 encryption..."
                    $plainSecret = Unprotect-SecretValue -Stored $storedSecret -Owner $window
                    $script:appConfig.ClientSecret = Protect-SecretValue -Plain $plainSecret -Owner $window
                    $script:appConfig | ConvertTo-Json | Out-File $appConfigPath -Encoding utf8
                    $script:appConfig.ClientSecret = $plainSecret
                } else {
                    $script:appConfig.ClientSecret = Unprotect-SecretValue -Stored $script:appConfig.ClientSecret -Owner $window
                }

                $expiry = [datetime]::Parse($script:appConfig.SecretExpiry)
                if ($expiry -gt (Get-Date).AddDays(1)) {
                    $needsNewApp = $false
                    Write-UILog "[Authenticate] Found saved app registration: $($script:appConfig.ClientID)"
                    Write-UILog "[Authenticate] Secret valid until: $($script:appConfig.SecretExpiry)"
                } else {
                    Write-UILog "[Authenticate] Saved app secret has expired. Will re-create."
                }
            }
        } catch [System.OperationCanceledException] {
            throw
        } catch {
            Write-UILog "[Authenticate] Saved config invalid, will re-create."
        }
    }

    if ($needsNewApp) {
        Write-UILog "[Authenticate] No valid app credentials found. Creating app registration (one-time setup)..."
        Write-UILog "[Authenticate] A browser window will open - please sign in with your admin account."
        $syncHash.Status = "Sign in with your admin account..."
        $syncHash.Progress = 40

        try {
            $wellKnownClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
            $tenantForAuth = if ($script:uploadTenantId) { $script:uploadTenantId } else { "organizations" }
            $redirectUri = "http://localhost"
            $scope = "https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All offline_access"

            $port = 8400
            $listenerRunning = $false
            for ($p = 8400; $p -le 8420; $p++) {
                try {
                    $listener = New-Object System.Net.HttpListener
                    $listener.Prefixes.Add("http://localhost:$p/")
                    $listener.Start()
                    $port = $p
                    $listenerRunning = $true
                    break
                } catch { continue }
            }
            if (-not $listenerRunning) { throw "Could not start HTTP listener on any port 8400-8420. Check firewall." }

            $redirectUri = "http://localhost:$port"
            $state = [guid]::NewGuid().ToString()

            $authUrl = "https://login.microsoftonline.com/$tenantForAuth/oauth2/v2.0/authorize?" +
                "client_id=$wellKnownClientId" +
                "&response_type=code" +
                "&redirect_uri=$([System.Uri]::EscapeDataString($redirectUri))" +
                "&scope=$([System.Uri]::EscapeDataString($scope))" +
                "&state=$state" +
                "&prompt=select_account"

            Write-UILog "[Authenticate] Opening browser for sign-in..."
            Start-Process $authUrl

            $authCode    = $null
            $deadline    = (Get-Date).AddMinutes(3)
            $context     = $null
            $userAborted = $false

            try {
                while ((Get-Date) -lt $deadline) {
                    & $pumpDispatcher
                    if ($syncHash.Cancelled -or -not $window -or -not $window.IsVisible) {
                        $userAborted = $true; break
                    }

                    $asyncResult = $listener.BeginGetContext($null, $null)
                    while (-not $asyncResult.IsCompleted) {
                        & $pumpDispatcher
                        if ($syncHash.Cancelled -or -not $window -or -not $window.IsVisible) {
                            $userAborted = $true; break
                        }
                        Start-Sleep -Milliseconds 100
                        if ((Get-Date) -ge $deadline) { break }
                    }
                    if ($userAborted) { break }
                    if (-not $asyncResult.IsCompleted) { break }

                    $context = $listener.EndGetContext($asyncResult)
                    $queryString = $context.Request.Url.Query
                    $queryParams = [System.Web.HttpUtility]::ParseQueryString($queryString)

                    if ($queryParams["error"]) {
                        $errorHtml = "<html><body><h2>Authentication Failed</h2><p>$($queryParams['error_description'])</p><p>You can close this window.</p></body></html>"
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorHtml)
                        $context.Response.ContentLength64 = $buffer.Length
                        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                        $context.Response.OutputStream.Close()
                        throw "Authentication failed: $($queryParams['error_description'])"
                    }

                    $authCode = $queryParams["code"]
                    if ($authCode) {
                        $successHtml = "<html><body><h2>Authentication Successful</h2><p>You can close this window and return to the application.</p></body></html>"
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($successHtml)
                        $context.Response.ContentLength64 = $buffer.Length
                        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                        $context.Response.OutputStream.Close()
                        break
                    }
                }
            } finally {
                try { if ($listener -and $listener.IsListening) { $listener.Stop() } } catch {}
                try { if ($listener) { $listener.Close() } } catch {}
            }

            if ($userAborted) {
                throw [System.OperationCanceledException]::new("AUTH_CANCELLED")
            }
            if (-not $authCode) { throw "Authentication timed out. Please try again." }
            Write-UILog "[Authenticate] Sign-in successful."

            $tokenBody = @{
                client_id    = $wellKnownClientId
                grant_type   = "authorization_code"
                code         = $authCode
                redirect_uri = $redirectUri
                scope        = $scope
            }
            $tokenResponse = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/$tenantForAuth/oauth2/v2.0/token" `
                -Body $tokenBody -ErrorAction Stop
            $accessToken = $tokenResponse.access_token

            $tokenParts = $accessToken.Split('.')
            $payload = $tokenParts[1]
            switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
            $tokenData = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
            $script:uploadTenantId = $tokenData.tid
            Write-UILog "[Authenticate] Signed in to tenant: $($script:uploadTenantId)"

            $graphHeaders = @{ Authorization = "Bearer $accessToken"; "Content-Type" = "application/json" }

            $syncHash.Status = "Creating app registration..."
            $syncHash.Progress = 45

            $appName = "PixelTech - Autopilot Hash Upload"
            $searchUrl = "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$appName'"
            $searchResult = Invoke-RestMethod -Method Get -Uri $searchUrl -Headers $graphHeaders -ErrorAction Stop
            $existingApp = $searchResult.value | Select-Object -First 1

            $appObjectId = $null
            $appClientId = $null

            if ($existingApp) {
                Write-UILog "[Authenticate] App '$appName' already exists: $($existingApp.appId)"
                $appObjectId = $existingApp.id
                $appClientId = $existingApp.appId
            } else {
                Write-UILog "[Authenticate] Creating app registration '$appName'..."
                $autopilotPermId = "5ac13192-7ace-4fcf-b828-1a26f28068ee"

                $appBody = @{
                    displayName = $appName
                    signInAudience = "AzureADMyOrg"
                    requiredResourceAccess = @(
                        @{
                            resourceAppId = "00000003-0000-0000-c000-000000000000"
                            resourceAccess = @(
                                @{ id = $autopilotPermId; type = "Role" }
                            )
                        }
                    )
                } | ConvertTo-Json -Depth 5

                $newApp = Invoke-RestMethod -Method Post `
                    -Uri "https://graph.microsoft.com/v1.0/applications" `
                    -Headers $graphHeaders -Body $appBody -ErrorAction Stop
                $appObjectId = $newApp.id
                $appClientId = $newApp.appId
                Write-UILog "[Authenticate] App created: $appClientId"

                Write-UILog "[Authenticate] Creating service principal..."
                $spBody = @{ appId = $appClientId } | ConvertTo-Json
                $newSP = Invoke-RestMethod -Method Post `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
                    -Headers $graphHeaders -Body $spBody -ErrorAction Stop
                $spId = $newSP.id
                Write-UILog "[Authenticate] Service principal created: $spId"

                Write-UILog "[Authenticate] Granting admin consent..."
                Start-Sleep -Seconds 5

                $graphSPResult = Invoke-RestMethod -Method Get `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" `
                    -Headers $graphHeaders -ErrorAction Stop
                $graphSPId = $graphSPResult.value[0].id

                $consentBody = @{
                    principalId = $spId
                    resourceId  = $graphSPId
                    appRoleId   = $autopilotPermId
                } | ConvertTo-Json

                try {
                    Invoke-RestMethod -Method Post `
                        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" `
                        -Headers $graphHeaders -Body $consentBody -ErrorAction Stop | Out-Null
                    Write-UILog "[Authenticate] Admin consent granted for DeviceManagementServiceConfig.ReadWrite.All"
                } catch {
                    Write-UILog "[Authenticate] WARNING: Could not grant admin consent: $($_.Exception.Message)"
                    Write-UILog "[Authenticate] Please go to https://entra.microsoft.com > App Registrations > '$appName' > API Permissions > Grant admin consent"
                    throw "Admin consent required. Please grant it in the Azure portal and try again."
                }
            }

            $syncHash.Status = "Creating app credentials..."
            $syncHash.Progress = 48

            Write-UILog "[Authenticate] Creating client secret..."
            $secretBody = @{
                passwordCredential = @{
                    displayName = "AutopilotHashUpload"
                    endDateTime = (Get-Date).AddYears(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
            } | ConvertTo-Json -Depth 3

            $secretResult = Invoke-RestMethod -Method Post `
                -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword" `
                -Headers $graphHeaders -Body $secretBody -ErrorAction Stop

            $clientSecret = $secretResult.secretText
            $secretExpiry = ([datetime]$secretResult.endDateTime).ToString("yyyy-MM-dd")
            Write-UILog "[Authenticate] Client secret created (expires: $secretExpiry)"

            Write-UILog "[Authenticate] Waiting for credential propagation..."
            $syncHash.Progress = 50
            Start-Sleep -Seconds 10

            $cfgToSave = @{
                ClientID     = $appClientId
                ClientSecret = (Protect-SecretValue -Plain $clientSecret -Owner $window)
                TenantID     = $script:uploadTenantId
                AppName      = $appName
                CreatedOn    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                SecretExpiry = $secretExpiry
                GroupTag     = $script:grouptag
            }
            $cfgToSave | ConvertTo-Json | Out-File $appConfigPath -Encoding utf8
            Write-UILog "[Authenticate] App credentials saved (secret encrypted) to AutopilotApp_Config.json"

            $script:appConfig = Get-Content $appConfigPath -Raw | ConvertFrom-Json
            if ($script:appConfig.ClientSecret) {
                $script:appConfig | Add-Member -NotePropertyName ClientSecret -NotePropertyValue (Unprotect-SecretValue -Stored $script:appConfig.ClientSecret -Owner $window) -Force
            }
        } catch [System.OperationCanceledException] {
            throw
        } catch {
            Write-UILog "[ERROR] $($_.Exception.Message)"
            $syncHash.ErrorOccurred = $true
            $syncHash.Status = "Failed: $($_.Exception.Message)"
            $syncHash.Progress = 100
            $syncHash.IsRunning = $false
            $btnStart.IsEnabled = $true
            $btnStart.Content = "Start Autopilot Collection"
            $btnAbort.IsEnabled = $false
            return
        }
    }

    # ═══════════════════════════════════════════════════════
    # PHASE 3: Upload Hash (background runspace)
    # ═══════════════════════════════════════════════════════
    $syncHash.AppClientID     = $script:appConfig.ClientID
    $syncHash.AppClientSecret = $script:appConfig.ClientSecret
    $syncHash.AppTenantID     = $script:appConfig.TenantID
    $syncHash.GroupTag        = $script:grouptag

    $script:bgRunspace = [runspacefactory]::CreateRunspace()
    $script:bgRunspace.ApartmentState = "STA"
    $script:bgRunspace.ThreadOptions = "UseNewThread"
    $script:bgRunspace.Open()
    $script:bgRunspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

    $script:bgPowerShell = [powershell]::Create()
    $script:bgPowerShell.Runspace = $script:bgRunspace

    [void]$script:bgPowerShell.AddScript({
        param($syncHash)

        function Write-Log {
            param([string]$text)
            $line = "[$(Get-Date -Format 'HH:mm:ss')] $text"
            $syncHash.OutputQueue.Add($line) | Out-Null
            Add-Content -Path $syncHash.LogFile -Value $line -ErrorAction SilentlyContinue
        }

        function Test-Cancelled {
            if ($syncHash.Cancelled) {
                Write-Log "[ABORT] Operation cancelled."
                throw "Operation cancelled by user."
            }
        }

        try {
            $syncHash.Phase = 3
            $syncHash.Status = "Uploading device hash to Intune..."
            $syncHash.Progress = 55

            $deviceSerial = (Get-CimInstance win32_bios).SerialNumber
            Write-Log "[Hash Upload] Device Serial: $deviceSerial"
            Write-Log "[Hash Upload] Using App: $($syncHash.AppClientID)"
            Write-Log "[Hash Upload] Tenant: $($syncHash.AppTenantID)"
            Write-Log "[Hash Upload] PowerShell: $($PSVersionTable.PSVersion) ($([System.IntPtr]::Size * 8)-bit)"

            Write-Log "[Hash Upload] Reading hardware hash from WMI..."
            $devDetail = Get-CimInstance -Namespace "root/cimv2/mdm/dmmap" `
                -Class "MDM_DevDetail_Ext01" `
                -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
                -ErrorAction Stop
            $rawHash = $devDetail.DeviceHardwareData
            if (-not $rawHash) { throw "Failed to read hardware hash from WMI (empty DeviceHardwareData)." }
            if ($rawHash -is [byte[]]) {
                $hardwareHash = [System.Convert]::ToBase64String($rawHash)
            } else {
                $hardwareHash = [string]$rawHash
            }
            Write-Log "[Hash Upload] Hardware hash captured ($([math]::Round($hardwareHash.Length / 1KB, 2)) KB base64)."

            $syncHash.Progress = 62
            Test-Cancelled

            Write-Log "[Hash Upload] Acquiring access token from Azure AD..."
            $tokenBody = @{
                client_id     = $syncHash.AppClientID
                client_secret = $syncHash.AppClientSecret
                scope         = "https://graph.microsoft.com/.default"
                grant_type    = "client_credentials"
            }
            $tokenUri = "https://login.microsoftonline.com/$($syncHash.AppTenantID)/oauth2/v2.0/token"
            try {
                $tokenResp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $tokenBody -ErrorAction Stop
            } catch {
                $detail = $_.Exception.Message
                if ($_.Exception.Response) {
                    try {
                        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                        $detail = $reader.ReadToEnd()
                    } catch {}
                }
                throw "Token request failed: $detail"
            }
            $accessToken = $tokenResp.access_token
            Write-Log "[Hash Upload] Token acquired (expires in $($tokenResp.expires_in) sec)."

            $graphHeaders = @{
                Authorization  = "Bearer $accessToken"
                "Content-Type" = "application/json"
            }

            $syncHash.Progress = 70
            Test-Cancelled

            $productKey = ""
            try {
                $productKey = (Get-CimInstance -Class SoftwareLicensingService -ErrorAction Stop).OA3xOriginalProductKey
            } catch {}

            $importBody = @{
                "@odata.type"             = "#microsoft.graph.importedWindowsAutopilotDeviceIdentity"
                serialNumber              = $deviceSerial
                productKey                = $productKey
                hardwareIdentifier        = $hardwareHash
                assignedUserPrincipalName = ""
            }
            if ($syncHash.GroupTag) { $importBody["groupTag"] = $syncHash.GroupTag }
            $importJson = $importBody | ConvertTo-Json -Depth 5

            Write-Log "[Hash Upload] POSTing hash to Intune (importedWindowsAutopilotDeviceIdentities)..."
            $importUri = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities"

            try {
                $importResult = Invoke-RestMethod -Method Post -Uri $importUri -Headers $graphHeaders -Body $importJson -ErrorAction Stop
            } catch {
                $detail = $_.Exception.Message
                if ($_.Exception.Response) {
                    try {
                        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                        $detail = $reader.ReadToEnd()
                    } catch {}
                }
                throw "Hash upload failed: $detail"
            }
            $importId = $importResult.id
            Write-Log "[Hash Upload] Accepted by Intune. Import ID: $importId"
            $syncHash.Progress = 80

            Write-Log "[Hash Upload] Waiting for Intune to process the import..."
            $pollUri = "$importUri/$importId"
            $deadline = (Get-Date).AddMinutes(10)
            $lastState = ""
            while ((Get-Date) -lt $deadline) {
                Test-Cancelled
                Start-Sleep -Seconds 5
                try {
                    $status = Invoke-RestMethod -Method Get -Uri $pollUri -Headers $graphHeaders -ErrorAction Stop
                } catch {
                    Write-Log "[Hash Upload] Poll warning: $($_.Exception.Message)"
                    continue
                }
                $state = $status.state.deviceImportStatus
                if ($state -ne $lastState) {
                    Write-Log "[Hash Upload] State: $state"
                    $lastState = $state
                }
                if ($state -eq "complete") {
                    Write-Log "[Hash Upload] Import complete."
                    break
                }
                if ($state -eq "error" -or $state -eq "failed") {
                    $errMsg = $status.state.deviceErrorName
                    if ($status.state.deviceErrorCode) { $errMsg = "$errMsg (code $($status.state.deviceErrorCode))" }
                    throw "Intune reported import error: $errMsg"
                }
                if ($syncHash.Progress -lt 78) { $syncHash.Progress = $syncHash.Progress + 1 }
            }
            if ($lastState -ne "complete") { throw "Timed out waiting for Intune import to complete." }

            $syncHash.Progress = 80
            Write-Log "[Hash Upload] Device hash registered in Intune."

            if (-not $syncHash.GroupTag) {
                Write-Log "[Profile] No Group Tag provided - skipping deployment profile wait."
                Write-Log "[Profile] Device is registered in Autopilot. Assign a profile manually in Intune, or re-run with a Group Tag."
                $syncHash.Progress = 95
                $syncHash.Status = "Hash uploaded (no profile expected without Group Tag)"
            } else {
                $syncHash.Status = "Waiting for Autopilot profile assignment..."
                Write-Log "[Profile] Looking up device in Autopilot inventory..."

                $escapedSerial = [System.Uri]::EscapeDataString($deviceSerial)
                $filterClause = [System.Uri]::EscapeDataString("contains(serialNumber,'$deviceSerial')")
                $deviceLookupUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=$filterClause"
                Write-Log "[Profile] Lookup URL: $deviceLookupUri"
                $apDevice = $null
                $lookupDeadline = (Get-Date).AddMinutes(3)
                while ((Get-Date) -lt $lookupDeadline) {
                    Test-Cancelled
                    Start-Sleep -Seconds 5
                    try {
                        $lookupResp = Invoke-RestMethod -Method Get -Uri $deviceLookupUri -Headers $graphHeaders -ErrorAction Stop
                        if ($lookupResp.value -and $lookupResp.value.Count -gt 0) {
                            $exact = $lookupResp.value | Where-Object { $_.serialNumber -eq $deviceSerial } | Select-Object -First 1
                            if (-not $exact) { $exact = $lookupResp.value[0] }
                            $apDevice = $exact
                            Write-Log "[Profile] Device found in Autopilot inventory. ID: $($apDevice.id)"
                            break
                        }
                    } catch {
                        $errBody = ""
                        try {
                            if ($_.Exception.Response) {
                                $stream = $_.Exception.Response.GetResponseStream()
                                $reader = New-Object System.IO.StreamReader($stream)
                                $errBody = $reader.ReadToEnd()
                            }
                        } catch {}
                        Write-Log "[Profile] Lookup warning: $($_.Exception.Message) $errBody"
                    }
                }
                if (-not $apDevice) {
                    throw "Device did not appear in Autopilot inventory within 3 minutes after import."
                }

                $syncHash.Progress = 82
                $profileDeviceUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($apDevice.id)?`$expand=deploymentProfile"

                $assignedStates = @("assignedInSync", "assignedOutOfSync", "assignedUnknownSyncState")
                $failedStates   = @("failed")
                $lastLogKey = ""
                $assignStart = Get-Date
                $assignDeadline = $assignStart.AddMinutes(15)
                $finalStatus = $null

                while ((Get-Date) -lt $assignDeadline) {
                    Test-Cancelled
                    Start-Sleep -Seconds 10
                    try {
                        $apCurrent = Invoke-RestMethod -Method Get -Uri $profileDeviceUri -Headers $graphHeaders -ErrorAction Stop
                    } catch {
                        Write-Log "[Profile] Poll warning: $($_.Exception.Message)"
                        continue
                    }
                    $assignState   = $apCurrent.deploymentProfileAssignmentStatus
                    $detailState   = $apCurrent.deploymentProfileAssignmentDetailedStatus
                    $profileObj    = $apCurrent.deploymentProfile
                    $profileName   = $null
                    if ($profileObj) { $profileName = $profileObj.displayName }
                    $assignedDT    = $apCurrent.deploymentProfileAssignedDateTime
                    $hasAssignedDT = $assignedDT -and ($assignedDT -notlike "0001-01-01*")

                    $elapsed = [int]((Get-Date) - $assignStart).TotalSeconds

                    switch ($assignState) {
                        "notAssigned" { $friendly = "Looking for a matching deployment profile..." }
                        "pending" {
                            if ($hasAssignedDT) { $friendly = "Profile scheduled - Intune is applying it now" }
                            else                { $friendly = "Intune is evaluating group membership..." }
                        }
                        "assignedInSync"            { $friendly = "Profile assigned and in sync" }
                        "assignedOutOfSync"         { $friendly = "Profile assigned (sync pending)" }
                        "assignedUnknownSyncState"  { $friendly = "Profile assigned (sync state unknown)" }
                        "failed"                    { $friendly = "Assignment failed - see Intune portal" }
                        default                     { $friendly = "Waiting for Intune..." }
                    }

                    $logKey = "$assignState|$profileName|$hasAssignedDT"
                    $isTransition = ($logKey -ne $lastLogKey -and $lastLogKey -ne "")
                    $prefix = if ($isTransition) { "[Profile] " + [char]0x2192 } else { "[Profile]  " }
                    $msg = "$prefix $friendly"
                    if ($profileName) { $msg += " - '$profileName'" }
                    $msg += " [${elapsed}s]"
                    Write-Log $msg
                    $lastLogKey = $logKey

                    $syncHash.Status = "$friendly (${elapsed}s)"

                    if ($assignedStates -contains $assignState) {
                        $finalStatus = $apCurrent
                        break
                    }
                    if ($failedStates -contains $assignState) {
                        throw "Intune reported profile assignment failure: $detailState"
                    }

                    if ($syncHash.Progress -lt 94) {
                        $syncHash.Progress = [math]::Min(94, 82 + [int]($elapsed / 8))
                    }
                }

                if (-not $finalStatus) {
                    Write-Log "[Profile] WARNING: Profile was not assigned within 15 minutes."
                    Write-Log "[Profile] The device is registered in Autopilot. An admin can assign a profile later in Intune."
                    throw "Profile assignment timed out. Device is registered but not yet assigned to a deployment profile - check group membership and profile assignments in Intune."
                }

                $syncHash.Progress = 95
                $finalProfileName = if ($finalStatus.deploymentProfile) { $finalStatus.deploymentProfile.displayName } else { "(profile bound - name pending sync)" }
                Write-Log "[Profile] Deployment profile '$finalProfileName' assigned successfully!"
                Write-Log "[Hash Upload] Device hash uploaded and profile assigned."
            }

            $syncHash.Phase = 4
            $syncHash.Status = "Completed successfully!"
            $syncHash.Progress = 100
            Write-Log "[Complete] Device is now registered in Intune Autopilot."

        } catch {
            if (-not $syncHash.Cancelled) {
                $errMsg = $_.Exception.Message
                Write-Log "[ERROR] $errMsg"
                $syncHash.ErrorOccurred = $true
                $syncHash.Status = "Failed: $errMsg"
                $syncHash.Progress = 100
            }
        } finally {
            $syncHash.IsRunning = $false
        }
    })

    [void]$script:bgPowerShell.AddArgument($syncHash)
    $script:bgPowerShell.BeginInvoke()
  } catch [System.OperationCanceledException] {
    try { $animTimer.Stop() } catch {}
    $syncHash.IsRunning     = $false
    $syncHash.ErrorOccurred = $false
    $syncHash.Cancelled     = $true
    $syncHash.Status        = "Cancelled by user"
    $syncHash.Progress      = 0
    $txtConsole.AppendText("[$(Get-Date -Format 'HH:mm:ss')] [Cancelled] Passphrase prompt dismissed. Ready.`r`n")
    $btnStart.IsEnabled     = $true
    $btnStart.Content       = "Start Autopilot Collection"
    $btnAbort.IsEnabled     = $false
    $lblStatus.Foreground   = $brushMuted
    $lblLogIndicator.Text   = "Idle"
    $lblLogIndicator.Foreground = $brushMuted
  } catch {
    try { $animTimer.Stop() } catch {}
    $syncHash.IsRunning     = $false
    $syncHash.ErrorOccurred = $true
    $syncHash.Status        = "Error: $($_.Exception.Message)"
    $txtConsole.AppendText("[$(Get-Date -Format 'HH:mm:ss')] [ERROR] $($_.Exception.Message)`r`n")
    $btnStart.IsEnabled     = $true
    $btnStart.Content       = "Start Autopilot Collection"
    $btnAbort.IsEnabled     = $false
  }
})

# ─── Closing cleanup ───────────────────────────────────────────────
$window.Add_Closing({
    try { if ($animTimer)           { $animTimer.Stop() } }                           catch {}
    try { if ($script:bgPowerShell) { $script:bgPowerShell.Stop(); $script:bgPowerShell.Dispose() } } catch {}
    try { if ($script:bgRunspace)   { $script:bgRunspace.Close();  $script:bgRunspace.Dispose()  } } catch {}
    $script:SessionPassphrase = $null
})

# ─── Show ──────────────────────────────────────────────────────────
[void]$window.ShowDialog()
