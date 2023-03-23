$url=$args[0]
$domain=$args[1]
$time=$args[2]
Set-Location "C:\Users\17862\AppData\Roaming\npm"
browsertime $url -b chrome --headless --output chrome_results --timeouts.browserStart 15000 --timeouts.pageCompleteCheck 15000 --resultDir "C:\Fingerprinting\$($domain)\Chrome\$($time)"