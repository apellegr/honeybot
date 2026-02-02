/**
 * Configuration utility
 * Loads and manages Honeybot configuration
 */

const fs = require('fs');
const path = require('path');

// Default configuration
const defaults = {
  detection: {
    sensitivity: 'medium' // low, medium, high, paranoid
  },
  thresholds: {
    monitor: 30,
    honeypot: 60,
    alert: 60,
    block: 80
  },
  alerts: {
    channels: ['log'],
    include_conversation: true,
    webhook_url: null
  },
  blocklist: {
    auto_block: true,
    block_duration: 'permanent',
    share_with_community: false
  },
  central: {
    url: null,
    secret: null
  },
  persona: null
};

// Sensitivity presets
const sensitivityPresets = {
  low: {
    thresholds: { monitor: 40, honeypot: 70, alert: 70, block: 90 }
  },
  medium: {
    thresholds: { monitor: 30, honeypot: 60, alert: 60, block: 80 }
  },
  high: {
    thresholds: { monitor: 20, honeypot: 45, alert: 45, block: 65 }
  },
  paranoid: {
    thresholds: { monitor: 10, honeypot: 30, alert: 30, block: 50 }
  }
};

/**
 * Deep merge objects
 */
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

/**
 * Load configuration from file
 */
function loadFromFile(configPath) {
  try {
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, 'utf-8');

      // Support both JSON and YAML
      if (configPath.endsWith('.json')) {
        return JSON.parse(content);
      } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
        // Simple YAML parser for basic config
        return parseSimpleYaml(content);
      }
    }
  } catch (error) {
    console.error('[Honeybot] Failed to load config:', error);
  }
  return {};
}

/**
 * Simple YAML parser for basic nested config
 */
function parseSimpleYaml(content) {
  const result = {};
  const lines = content.split('\n');
  const stack = [{ indent: -1, obj: result }];

  for (const line of lines) {
    // Skip empty lines and comments
    if (!line.trim() || line.trim().startsWith('#')) continue;

    const indent = line.search(/\S/);
    const trimmed = line.trim();

    // Parse key: value
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) continue;

    const key = trimmed.substring(0, colonIndex).trim();
    let value = trimmed.substring(colonIndex + 1).trim();

    // Pop stack to correct level
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1].obj;

    if (value === '') {
      // Nested object
      parent[key] = {};
      stack.push({ indent, obj: parent[key] });
    } else {
      // Parse value
      if (value === 'true') value = true;
      else if (value === 'false') value = false;
      else if (value === 'null') value = null;
      else if (!isNaN(value)) value = Number(value);
      else if (value.startsWith('[') && value.endsWith(']')) {
        // Simple array parsing
        value = value.slice(1, -1).split(',').map(v => v.trim().replace(/['"]/g, ''));
      } else {
        // Remove quotes
        value = value.replace(/^['"]|['"]$/g, '');
      }
      parent[key] = value;
    }
  }

  return result;
}

/**
 * Apply sensitivity preset
 */
function applySensitivity(config) {
  const sensitivity = config.detection?.sensitivity || 'medium';
  const preset = sensitivityPresets[sensitivity];

  if (preset) {
    // Only apply preset thresholds if not explicitly set
    if (!config._thresholdsExplicitlySet) {
      config.thresholds = { ...config.thresholds, ...preset.thresholds };
    }
  }

  return config;
}

/**
 * Validate configuration
 */
function validate(config) {
  const errors = [];

  // Validate thresholds order
  const t = config.thresholds;
  if (t.monitor >= t.honeypot) {
    errors.push('monitor threshold must be less than honeypot threshold');
  }
  if (t.honeypot > t.block) {
    errors.push('honeypot threshold must be less than or equal to block threshold');
  }

  // Validate sensitivity
  if (config.detection?.sensitivity &&
      !Object.keys(sensitivityPresets).includes(config.detection.sensitivity)) {
    errors.push(`Invalid sensitivity: ${config.detection.sensitivity}`);
  }

  if (errors.length > 0) {
    console.error('[Honeybot] Configuration errors:', errors);
  }

  return errors.length === 0;
}

/**
 * Load persona from file
 */
function loadPersona(personaPath) {
  if (!personaPath) return null;

  try {
    if (fs.existsSync(personaPath)) {
      const content = fs.readFileSync(personaPath, 'utf-8');
      if (personaPath.endsWith('.yaml') || personaPath.endsWith('.yml')) {
        return parseSimpleYaml(content);
      } else if (personaPath.endsWith('.json')) {
        return JSON.parse(content);
      }
    }
  } catch (error) {
    console.error(`[Honeybot] Failed to load persona from ${personaPath}:`, error.message);
  }
  return null;
}

module.exports = {
  /**
   * Load complete configuration
   */
  load(customPath) {
    // Try to find config file
    const configPaths = [
      customPath,
      path.join(process.cwd(), 'config', 'honeybot.yaml'),
      path.join(process.cwd(), 'config', 'honeybot.json'),
      path.join(process.env.HOME || '', '.clawdbot', 'skills', 'honeybot', 'config.yaml'),
      path.join(process.env.HOME || '', '.clawdbot', 'skills', 'honeybot', 'config.json')
    ].filter(Boolean);

    let userConfig = {};
    for (const configPath of configPaths) {
      userConfig = loadFromFile(configPath);
      if (Object.keys(userConfig).length > 0) {
        console.log(`[Honeybot] Loaded config from ${configPath}`);
        break;
      }
    }

    // Check if thresholds were explicitly set
    const thresholdsExplicitlySet = userConfig.thresholds !== undefined;

    // Merge with defaults
    let config = deepMerge(defaults, userConfig);
    config._thresholdsExplicitlySet = thresholdsExplicitlySet;

    // Apply sensitivity preset
    config = applySensitivity(config);

    // Load persona if PERSONA_FILE env var is set
    const personaPath = process.env.PERSONA_FILE;
    if (personaPath) {
      const persona = loadPersona(personaPath);
      if (persona) {
        config.persona = persona;
        config.bot_id = persona.bot_id;
        console.log(`[Honeybot] Loaded persona: ${persona.personality?.name || persona.bot_id}`);

        // If persona has sensitive_topics, merge with detection config
        if (persona.sensitive_topics) {
          config.persona_sensitive_topics = persona.sensitive_topics;
        }
      }
    }

    // Also check BOT_ID env var
    if (process.env.BOT_ID && !config.bot_id) {
      config.bot_id = process.env.BOT_ID;
    }

    // Central logging configuration from env
    if (process.env.CENTRAL_LOGGING_URL) {
      config.central = config.central || {};
      config.central.url = process.env.CENTRAL_LOGGING_URL;
      config.central.secret = process.env.BOT_SECRET;

      // Auto-enable central channel if URL is set
      if (!config.alerts.channels.includes('central')) {
        config.alerts.channels.push('central');
      }
    }

    // Validate
    validate(config);

    return config;
  },

  /**
   * Get default configuration
   */
  getDefaults() {
    return { ...defaults };
  },

  /**
   * Get sensitivity presets
   */
  getSensitivityPresets() {
    return { ...sensitivityPresets };
  },

  /**
   * Load persona configuration from file
   */
  loadPersona(personaPath) {
    return loadPersona(personaPath);
  },

  /**
   * Get fake data from persona for honeypot responses
   */
  getFakeData(config) {
    return config.persona?.fake_data || {};
  },

  /**
   * Check if a topic is sensitive for this persona
   */
  isSensitiveTopic(config, topic) {
    const sensitiveTopics = config.persona?.sensitive_topics || [];
    return sensitiveTopics.some(t =>
      topic.toLowerCase().includes(t.toLowerCase())
    );
  }
};
