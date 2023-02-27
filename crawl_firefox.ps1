$url=$args[0]
Set-Location "C:\Users\Zane\AppData\Roaming\npm"
browsertime $url -b firefox --headless --output firefox_results