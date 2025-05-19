# tor-hide
 
This script re-routes all pc network traffic through the tor network making you invisible on the internet. 

It is only well compatible with linux machines. 

Run it with sudo privileges. install any packages it needs to run and then you only need to run it once whenever you start the machine. 

└─$ sudo ./hide.sh --help
[sudo] password for <username>: 
2025-05-19 06:30:31 - [INFO] Checking dependencies...
Enhanced Tor Transparent Proxy Script v2.0.0

Usage: ./hide.sh {on|off|status|newid|emergency-stop|help}

Commands:
  on             Enable Tor routing (all traffic goes through Tor)
  off            Disable Tor routing (restore normal networking)
  status         Check the current status of Tor routing
  newid          Request a new Tor identity/circuit
  emergency-stop Immediately block all network traffic (kill switch)
  help           Show this help message

This script configures your system to route all internet traffic through 
the Tor network for anonymity.