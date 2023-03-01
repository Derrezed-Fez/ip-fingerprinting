$url=$args[0]
Set-Location "C:\Users\Zane\AppData\Roaming\npm"
browsertime $url --chrome.binaryPath "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" --headless --output edge_results --timeouts.browserStart 15000 --timeouts.pageCompleteCheck 15000