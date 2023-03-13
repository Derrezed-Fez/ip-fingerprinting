$url=$args[0]
Set-Location "C:\Users\psych\AppData\Roaming\npm"
browsertime $url -b edge --headless --output edge_results --timeouts.browserStart 15000 --timeouts.pageCompleteCheck 15000 --resultDir "F:\\crawler"