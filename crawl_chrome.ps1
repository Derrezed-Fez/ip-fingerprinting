$url=$args[0]
Set-Location "C:\Users\Zane\AppData\Roaming\npm"
browsertime $url -b chrome --headless --output chrome_results