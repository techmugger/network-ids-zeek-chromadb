# custom.sig - example signature-based detection rules for Zeek's
# built-in signature framework (Snort-like syntax).
#
# NOTE: the old "sig-nmap-scan" rule (any TCP to port 80) was removed
# because it fired on ALL ordinary HTTP traffic, not actual Nmap
# scans - real scan detection now lives in local.zeek as behavioral
# Zeek scripting logic (ScanDetect module), which tracks distinct
# ports-per-source over time instead of guessing from one packet.

signature sig-modbus-diagnostic-abuse {
    ip-proto == tcp
    dst-port == 502
    payload /^\x00.*\x08\x00/
    event "Suspicious Modbus diagnostic function code usage"
}

signature sig-sql-injection-attempt {
    ip-proto == tcp
    dst-port == 80
    http-request /.*(\%27)|(\')|(\-\-)|(\%23)|(#).*/
    event "Possible SQL injection pattern in HTTP request"
}

signature sig-plaintext-ftp-creds {
    ip-proto == tcp
    dst-port == 21
    payload /^USER .*/
    event "Plaintext FTP credentials observed"
}
