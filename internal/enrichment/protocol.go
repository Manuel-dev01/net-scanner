package enrichment

// wellKnownPorts maps port numbers to application-layer protocol names.
var wellKnownPorts = map[int]string{
	20:    "FTP-Data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:    "POP3",
	143:    "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5672:  "AMQP",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	9090:  "Prometheus",
	27017: "MongoDB",
}

// IdentifyProtocol returns the application-layer protocol for a given port.
// Falls back to the transport layer name if the port is unknown.
func IdentifyProtocol(port int, transport string) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return transport
}

// IdentifyService returns a human-readable service name for a port.
func IdentifyService(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return "unknown"
}
