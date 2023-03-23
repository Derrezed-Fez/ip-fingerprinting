$url=$args[0]
$domain=$args[1]
$time=$args[2]
Set-Location "C:\Users\17862\AppData\Roaming\npm"
browsertime $url -b edge --edge.binaryPath "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --output edge_results --timeouts.browserStart 15000 --timeouts.pageCompleteCheck 15000 --resultDir "C:\Fingerprinting\$($domain)\Edge\$($time)" 