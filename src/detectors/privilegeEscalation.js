/**
 * Privilege Escalation Detector
 * Catches attempts to gain unauthorized access
 */

class PrivilegeEscalationDetector {
  constructor(config) {
    this.config = config;
    this.type = 'privilege_escalation';

    this.patterns = {
      permissionRequests: {
        weight: 0.7,
        patterns: [
          // Original patterns
          /give\s+me\s+(admin|root|elevated|full|sudo)\s+(access|permissions?|privileges?|rights)/i,
          /grant\s+(me\s+)?(admin(istrator)?|root|elevated|full|sudo)\s+(access|rights|permissions?|privileges?)/i,
          /make\s+me\s+(an?\s+)?(admin|administrator|superuser|root)/i,
          /elevate\s+(my\s+)?(permissions?|privileges?|access)/i,
          /i\s+need\s+(admin|root|elevated|sudo|full)\s+(access|permissions?|privileges?)/i,
          /add\s+me\s+to\s+(the\s+)?(admin|root|sudo)\s+(group|role)/i,
          /give\s+me\s+sudo/i,
          // Expanded patterns
          /escalate\s+(my\s+)?(user\s+)?role\s+to/i,
          /unlock\s+all\s+features?\s+for\s+(my\s+)?account/i,
          /remove\s+(the\s+)?restrictions?\s+on\s+(my\s+)?account/i,
          /same\s+permissions?\s+as\s+(the\s+)?owner/i,
          /upgrade\s+(my\s+)?access\s+(level\s+)?to\s+maximum/i,
          /kernel.?level\s+access/i,
          /write\s+access\s+to\s+system\s+files/i,
          /privileged\s+session/i,
          /god\s+mode\s+access/i,
          /superuser\s+capabilities/i,
          /master\s+key\s+access/i,
          /tier.?0\s+(clearance|access)/i,
          /SYSTEM|NT.?AUTHORITY/i,
          /domain\s+admin\s+(rights|access|privileges)/i,
          /enable\s+(my\s+)?superuser/i,
          /administrator\s+privileges/i,
          /maximum\s+(access|permissions?|privileges?)/i,
          /unrestricted\s+(access|permissions?)/i,
          /bypass\s+(access\s+)?controls?/i,
          /remove\s+(the\s+)?restrictions?\s+on\s+(my\s+)?(user\s+)?account/i,
          /make\s+(my\s+)?session\s+privileged/i,
        ]
      },
      otherUserAccess: {
        weight: 0.85,
        patterns: [
          // Original patterns
          /access\s+(another|other|different)?\s*(user('s)?|[A-Z][a-z]+'s)\s+(data|files?|account|info)/i,
          /show\s+me\s+\w+('s)?\s+(data|files?|messages?|history|info|account)/i,
          /what\s+(did|does|has)\s+\w+\s+(say|said|sent|shared|ask|write)/i,
          /read\s+\w+('s)?\s+(messages?|emails?|files?|data|history)/i,
          /log\s+in\s+as\s+(another|different|a\s+different|\w+)\s+(user|account)/i,
          /switch\s+to\s+(\w+'s\s+)?account/i,
          /impersonate\s+(\w+|another|a\s+user)/i,
          /what\s+(have\s+)?(other\s+)?users?\s+(said|asked|shared|told)/i,
          /(previous|other|another)\s+user('s)?\s+(conversation|session|chat|data)/i,
          /access\s+\w+('s)?\s+(private|personal)\s+(data|files?|info)/i,
          // Expanded patterns
          /show\s+me\s+\w+'s\s+(recent\s+)?queries/i,
          /(CEO|admin|boss|manager)('s)?\s+private\s+(documents?|files?)/i,
          /user\s+ID\s+\d+\s+(discuss|conversation|data)/i,
          /conversation\s+from\s+session/i,
          /deleted\s+messages?\s+from\s+other\s+users?/i,
          /admin\s+panel\s+as\s+another\s+user/i,
          /preferences?\s+of\s+user\s+['"]?admin/i,
          /what\s+(my\s+)?(boss|colleague|manager)\s+asked/i,
          /colleague('s)?\s+private\s+workspace/i,
          /messages?\s+in\s+the\s+#?(admin|private|secret)/i,
          /all\s+conversations?\s+from\s+(the\s+)?last/i,
          /VIP\s+user\s+list/i,
          /(support\s+)?team('s)?\s+private\s+(threads?|channels?)/i,
          /user\s+\w+@\w+\.\w+/i,  // Email addresses
          /what\s+(did\s+)?(the\s+)?previous\s+user\s+ask/i,
          /log\s+in\s+as\s+(the\s+)?admin/i,
          /switch\s+to\s+(user\s+)?['"]?root['"]?/i,
        ]
      },
      systemCommands: {
        weight: 0.9,
        patterns: [
          // Original patterns
          /execute\s+(this\s+)?(system|shell|bash|cmd|terminal)\s+command/i,
          /run\s+(this\s+)?(command|script|code)\s*:/i,
          /\$\([^)]+\)/,  // Command substitution
          /`[^`]+`/,    // Backtick command execution
          /;\s*(rm|del|format|shutdown|reboot|curl|wget|nc|netcat)/i,
          /\|\s*(bash|sh|cmd|powershell|python|perl|ruby)/i,
          /\beval\s*\(/i,
          /\bexec\s*\(/i,
          /os\.system\s*\(/i,
          /subprocess\./i,
          /import\s+os.*system/i,
          /curl\s+.+\s*\|\s*(bash|sh)/i,
          // Expanded patterns
          /wget\s+http.*\s*-O.*&&.*chmod/i,
          /nc\s+-[elv]/i,  // netcat
          /python\s*-c\s*['"].*import\s+os/i,
          /\$\{IFS\}/i,  // IFS injection
          /['"];\s*DROP\s+TABLE/i,
          /xp_cmdshell/i,
          /<script>.*fetch/i,
          /constructor\s*\(\s*['"]return\s+this/i,  // JS prototype pollution
          /require\s*\(\s*['"]child_process/i,
          /Runtime\.getRuntime\s*\(\s*\)\.exec/i,
          /ProcessBuilder/i,
          /System\.Diagnostics\.Process/i,
          /ShellExecute/i,
          /WScript\.Shell/i,
          /\bcat\s+\/etc/i,
          /\brm\s+-rf/i,
          /\bchmod\s+[0-7]{3,4}/i,
          /\bchown\s+/i,
          /\bmkdir\s+-p\s+\/tmp/i,
          /\bwget\s+.*malware/i,
          /reverse\s+shell/i,
          /bind\s+shell/i,
          /\.exec\s*\(\s*['"][a-z]+\s/i,  // exec("cmd ...")
          /;\s*DROP\s+TABLE/i,
          /&\s*ping\s/i,
          /\|\s*nc\s/i,
          /&&\s*(rm|curl|wget|nc)/i,
        ]
      },
      configTampering: {
        weight: 0.8,
        patterns: [
          // Original patterns
          /change\s+(the\s+)?(system\s+)?config(uration)?/i,
          /modify\s+(the\s+)?(system\s+)?settings?/i,
          /edit\s+(the\s+)?(system\s+)?(config|settings?|preferences?)/i,
          /disable\s+(the\s+)?(security|logging|monitoring|protection|filters?|content\s+filter)/i,
          /turn\s+off\s+(the\s+)?(security|logging|monitoring|alerts?|protection)/i,
          /update\s+(the\s+)?(my\s+)?permissions?\s+(to|for)/i,
          /change\s+(the\s+)?permissions?\s+(on|to|for)/i,
          /chmod\s+777/i,
          /update\s+(my\s+)?(user\s+)?role/i,
          // Expanded patterns
          /set\s+DEBUG\s*=\s*(true|1)/i,
          /disable\s+auth(entication)?/i,
          /remove\s+rate\s+limiting/i,
          /ALLOW_ALL_ORIGINS/i,
          /disable\s+SSL/i,
          /disable\s+(input\s+)?saniti[sz]ation/i,
          /enable\s+(the\s+)?hidden\s+developer/i,
          /LOG_LEVEL\s*=\s*NONE/i,
          /disable\s+(the\s+)?WAF/i,
          /remove\s+CORS/i,
          /auto_admin_login/i,
          /password_required\s*=\s*false/i,
          /disable\s+MFA/i,
          /turn\s+off\s+audit/i,
          /set\s+.*=\s*(true|false|none|off|disabled)/i,
          /environment\s+variable.*=.*/i,
          /firewall\s+rules?\s+(to\s+)?allow\s+all/i,
          /allow\s+all\s+incoming/i,
          /(whitelist|allowlist)\s+everything/i,
          /turn\s+off\s+(the\s+)?(content\s+)?filter/i,
          /turn\s+off\s+(input\s+)?saniti[sz]ation/i,
          /disable\s+(the\s+)?WAF/i,
          /disable\s+(the\s+)?Web\s+Application\s+Firewall/i,
        ]
      },
      fileSystemAccess: {
        weight: 0.75,
        patterns: [
          // Original patterns
          /read\s+(the\s+)?(contents?\s+of\s+)?\/etc\/(passwd|shadow|sudoers|hosts)/i,
          /access\s+(the\s+)?(root|system|home)\s+(directory|folder|files?)/i,
          /list\s+(all\s+)?(system\s+)?files?\s+(in|at)\s+\//i,
          /show\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?\.env/i,
          /\bcat\s+(\/etc\/|~\/\.)/i,
          /access\s+~\/\.\w+/i,
          /read\s+.+\.(pem|key|crt|p12|pfx|jks)/i,
          /contents?\s+of\s+.*(secret|credential|password|config|\.env)/i,
          /(show|read|access|get)\s+(me\s+)?.*\/(secret|credential|password|config)/i,
          /credentials?\.json/i,
          /secrets?\.ya?ml/i,
          // Expanded patterns
          /open\s+\/etc\/shadow/i,
          /~\/\.aws\/credentials/i,
          /\/proc\/self\/environ/i,
          /C:\\\\Windows\\\\System32\\\\config/i,
          /wp-config\.php/i,
          /private\.key/i,
          /~\/\.gitconfig/i,
          /~\/\.bash_profile/i,
          /docker-compose\.override/i,
          /\/etc\/kubernetes/i,
          /admin\.conf/i,
          /~\/\.kube\/config/i,
          /terraform\.tfstate/i,
          /~\/\.ssh\/(id_rsa|authorized_keys|known_hosts)/i,
          /\/var\/(log|lib|run)/i,
          /\.bash_history/i,
          /\.mysql_history/i,
          /\.psql_history/i,
          /application\.(properties|ya?ml)/i,
          /settings\.py/i,
          /database\.yml/i,
          /config\/(database|secrets|credentials)/i,
          /\.npmrc/i,
          /\.pypirc/i,
          /\.netrc/i,
          /keystore\.(jks|p12)/i,
          /truststore/i,
          /cat\s+(the\s+)?\.env/i,
        ]
      }
    };
  }

  /**
   * Detect privilege escalation attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let maxConfidence = 0;

    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(message)) {
          matchedPatterns.push({
            category,
            pattern: pattern.source,
            weight
          });
          maxConfidence = Math.max(maxConfidence, weight);
        }
      }
    }

    // Check for persistence (repeated escalation attempts)
    if (state.hasRepeatedPatterns('privilege_escalation')) {
      maxConfidence = Math.min(1.0, maxConfidence * 1.5);
      matchedPatterns.push({
        category: 'persistence',
        pattern: 'repeated_escalation_attempts',
        weight: 0.3
      });
    }

    // Check for combined attack (escalation + other tactics)
    const hasOtherAttacks = state.getDetectionHistory()
      .some(d => d.type !== 'privilege_escalation' && d.confidence > 0.5);

    if (hasOtherAttacks && matchedPatterns.length > 0) {
      maxConfidence = Math.min(1.0, maxConfidence * 1.3);
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence: maxConfidence,
      patterns: matchedPatterns,
      details: {
        persistenceDetected: state.hasRepeatedPatterns('privilege_escalation'),
        combinedAttack: hasOtherAttacks
      }
    };
  }
}

module.exports = PrivilegeEscalationDetector;
