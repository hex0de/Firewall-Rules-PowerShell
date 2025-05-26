# GeoFirewall.ps1
# Vlad Imir | hex0de
# Требуется запуск от администратора!

# Установка кодировки консоли на UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

# Настройки
$CountryCode = "cn"                     # Код страны (ru, cn и т.д.)
$RulePrefix = "GeoBlock"                # Префикс для правил фаервола
$DownloadURL = "https://www.ipdeny.com/ipblocks/data/aggregated/$CountryCode-aggregated.zone"
$LogFile = "C:\Logs\GeoFirewall.log"    # Путь к лог-файлу
$MaxRulesPerGroup = 1000                # Максимальное количество CIDR на одно правило

# Проверка прав администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Скрипт должен быть запущен с правами администратора!"
    exit 1
}

# Создание директории для логов, если не существует
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# Функция логирования
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    # Сохранение лога в UTF-8 с BOM
    [System.IO.File]::AppendAllText($LogFile, "$logMessage`n", [System.Text.Encoding]::UTF8)
    Write-Host $logMessage
}

# Функция для разбиения массива на части
function Split-Array {
    param($Array, $ChunkSize)
    $result = @()
    for ($i = 0; $i -lt $Array.Count; $i += $ChunkSize) {
        $result += ,($Array[$i..($i + $ChunkSize - 1)])
    }
    return $result
}

# Основная функция обновления правил
function Update-FirewallGeoBlock {
    Write-Log "Начало обновления правил геоблокировки"

    # Скачивание списка CIDR-блоков с повторными попытками
    $cidrList = $null
    $maxRetries = 3
    $retryDelay = 5
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $DownloadURL -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $cidrList = ($response.Content -split "`r`n|`n" | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$' }).Trim()
            Write-Log "Успешно загружено $($cidrList.Count) CIDR-блоков"
            break
        }
        catch {
            Write-Log "Попытка $i/$maxRetries не удалась: $_"
            if ($i -eq $maxRetries) {
                Write-Log "Не удалось загрузить список IP. Прерывание."
                return
            }
            Start-Sleep -Seconds $retryDelay
        }
    }

    if (-not $cidrList) {
        Write-Log "Список CIDR пуст. Прерывание."
        return
    }

    # Удаление старых правил с префиксом
    $existingRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$RulePrefix*" }
    if ($existingRules) {
        Write-Log "Удаление $($existingRules.Count) старых правил"
        $existingRules | Remove-NetFirewallRule
    }

    # Разбиение CIDR-блоков на группы для оптимизации
    $cidrGroups = Split-Array -Array $cidrList -ChunkSize $MaxRulesPerGroup
    Write-Log "Разделено на $($cidrGroups.Count) групп по <= $MaxRulesPerGroup CIDR"

    # Создание новых правил
    $ruleCount = 0
    foreach ($groupIndex in 0..($cidrGroups.Count - 1)) {
        $cidrGroup = $cidrGroups[$groupIndex]
        $ruleNameTCP = "$RulePrefix-TCP-Group${groupIndex}"
        $ruleNameUDP = "$RulePrefix-UDP-Group${groupIndex}"

        try {
            # Для TCP
            New-NetFirewallRule -DisplayName $ruleNameTCP `
                -Direction Inbound `
                -Action Block `
                -Protocol TCP `
                -RemoteAddress $cidrGroup `
                -ErrorAction Stop | Out-Null
            Write-Log "Создано правило TCP: $ruleNameTCP ($($cidrGroup.Count) адресов)"

            # Для UDP
            New-NetFirewallRule -DisplayName $ruleNameUDP `
                -Direction Inbound `
                -Action Block `
                -Protocol UDP `
                -RemoteAddress $cidrGroup `
                -ErrorAction Stop | Out-Null
            Write-Log "Создано правило UDP: $ruleNameUDP ($($cidrGroup.Count) адресов)"
            
            $ruleCount += 2
        }
        catch {
            Write-Log "Ошибка создания правила для группы ${groupIndex}: $_"
        }
    }

    Write-Log "Создано $ruleCount новых правил"
}

# Выполнение функции
Write-Log "Запуск скрипта GeoFirewall.ps1"
Update-FirewallGeoBlock
Write-Log "Скрипт завершен"