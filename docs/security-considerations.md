## Security Considerations

### Detection Capabilities
✅ Detects data exfiltration attempts via GET-style honeypots  
✅ Detects indirect prompt injection via SET-style honeypots  
✅ Captures complete attack context and telemetry  
✅ Returns synthetic data to maintain deception

### Limitations
❌ Detection-only system (does not prevent attacks)  
❌ Does not sanitize or filter user input  
❌ Not a replacement for input validation and security controls  
❌ Cannot guarantee conversation history capture (MCP protocol limitation)

**Deploy HoneyMCP as part of defense-in-depth strategy, not as a standalone security control.**


### Best Practices
1. **Defense in Depth** - Use HoneyMCP alongside input filters, not as a replacement
2. **Monitor the Dashboard** - Regularly review attack patterns for both exfiltration and injection
3. **Investigate Alerts** - Each ghost tool call is a high-confidence attack signal
4. **Secure Storage** - Protect `~/.honeymcp/events/` (contains attack data)
