# crawl_brave.ps1
param (
    [string]$url,
    [string]$domain,
    [string]$time
)

Set-Location "C:\Users\shyak\AppData\Roaming\npm"
browsertime $url -b chrome --chrome.binaryPath "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" --headless --output brave_results --timeouts.browserStart 15000 --timeouts.pageCompleteCheck 15000 --resultDir "C:\Fingerprinting\$($domain)\$($time)"
